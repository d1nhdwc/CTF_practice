#!/usr/bin/env python3
from pwn import *
import ctypes
import time

PORT = 62222
HOST = "fickle-tempest.picoctf.net"
e = context.binary = ELF('./seed_spring', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return e.process()

p = conn()

#GDB()
libc = ctypes.CDLL("libc.so.6")
seed = int(time.time())
libc.srand(seed)

for i in range(30):
	result = libc.rand() & 0xf
	p.sendlineafter(b"height: ", str(result).encode())
	print("the result:", result)

p.interactive()