#!/usr/bin/env python3
from pwn import *
import base64

PORT = 21033
HOST = "host3.dreamhack.games"

p = remote(HOST, PORT)

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

with open("patched_bin", "rb") as f:
    payload = base64.b64encode(f.read())

sla(b'\n', payload)

p.interactive()