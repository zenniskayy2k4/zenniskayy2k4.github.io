---
title: API Hashing trong loader và backdoor Chrysalis của Lotus Blossom
date: 2026-02-27 09:00 +0700
tags: [malware, reversing, apt, lotus-blossom]
categories: [Malware Analysis]
author: ZennisKayy
description: Ghi chú kỹ thuật về API hashing trong log.dll và backdoor Chrysalis, dựa trên phân tích được Rapid7 công bố tháng 2/2026.
image:
  path: /assets/img/api_hashing/notepad++.webp
---

Đầu tháng 2/2026, Rapid7 công bố phân tích một chuỗi lây nhiễm liên quan đến hạ tầng phân phối của Notepad++. Mẫu được phân tích triển khai một backdoor mới mà Rapid7 đặt tên là **Chrysalis** và đánh giá, với mức tin cậy trung bình, có liên quan đến **Lotus Blossom**[^r7-report]. MITRE ATT&CK theo dõi nhóm này dưới mã **G0030**, cùng một số tên khác như Spring Dragon, Raspberry Typhoon và Billbug[^mitre-lbg].

Bài viết này tập trung vào cách loader `log.dll` và module Chrysalis phân giải Windows API ở runtime. Nội dung về mẫu cụ thể được diễn giải từ báo cáo công khai của Rapid7; tôi không có mẫu gốc để xác nhận độc lập từng lệnh máy hoặc xây dựng chữ ký phát hiện đã được kiểm thử.

## 1. Bối cảnh của chuỗi lây nhiễm

Theo Rapid7, dấu vết trên máy nạn nhân cho thấy `notepad++.exe` chạy `GUP.exe`, sau đó một `update.exe` đáng ngờ được tải từ `95.179.213[.]0`. Rapid7 cũng lưu ý rằng dữ liệu pháp chứng của họ **không đủ để xác định chính xác** cơ chế updater hoặc plugin nào đã bị lợi dụng trong trường hợp này[^r7-report]. Vì vậy, mô tả phù hợp hơn là hạ tầng phân phối cập nhật bị lạm dụng để chuyển hướng có chọn lọc, không phải mã nguồn Notepad++ bị sửa trực tiếp[^r7-followup].

`update.exe` là một NSIS installer chứa các thành phần chính sau:

- `BluetoothService.exe`: bản đổi tên của Bitdefender Submission Wizard, được dùng làm chương trình hợp lệ cho DLL side-loading.
- `log.dll`: DLL độc hại được nạp cạnh `BluetoothService.exe`.
- `BluetoothService`: blob shellcode đã mã hóa, không có phần mở rộng.

Installer tạo thư mục `%AppData%\Bluetooth`, chép các file vào đó, đặt thuộc tính ẩn rồi chạy `BluetoothService.exe`. Hai export `LogInit` và `LogWrite` trong `log.dll` được chương trình hợp lệ gọi. `LogInit` nạp blob `BluetoothService`; `LogWrite` giải mã rồi chuyển thực thi sang stage tiếp theo[^r7-report].

Chuỗi này tương ứng với một số kỹ thuật ATT&CK mà Rapid7 liệt kê, gồm DLL Side-Loading (`T1574.002`), Dynamic API Resolution (`T1027.007`), Reflective Code Loading (`T1620`) và Web Protocols (`T1071.001`)[^r7-report].

## 2. API hashing giải quyết vấn đề gì?

Một PE thông thường có thể để lộ tên API qua Import Address Table (IAT), chẳng hạn `VirtualAlloc` hoặc `CreateProcessW`. Với dynamic API resolution, chương trình tự duyệt các module đang được nạp, đọc Export Directory rồi tìm địa chỉ hàm ở runtime. Tên export có thể được so sánh trực tiếp hoặc chuyển thành một giá trị hash trước khi so sánh.

Luồng xử lý thường có dạng:

1. Lấy danh sách module từ PEB, hoặc bắt đầu từ một module handle đã biết.
2. Parse PE header và Export Directory của từng module.
3. Duyệt mảng tên export.
4. Tính hash cho từng tên.
5. So sánh với hash được lưu trong mẫu.
6. Dùng ordinal tương ứng để lấy RVA, sau đó quy đổi thành địa chỉ hàm.

Kỹ thuật này làm giảm số tên API xuất hiện dưới dạng chuỗi hoặc import tĩnh. Nó không làm API trở nên “vô hình”: resolver, vòng lặp parse export, các hằng số hash và địa chỉ trả về ở runtime vẫn là những điểm có thể phân tích. MITRE xếp hành vi này vào **Obfuscated Files or Information: Dynamic API Resolution (`T1027.007`)**[^mitre-dynamic-api].

## 3. Hai resolver trong chuỗi Chrysalis

### 3.1. Resolver của `log.dll`

Rapid7 mô tả `log.dll` dùng FNV-1a với:

- offset basis: `0x811C9DC5`
- prime: `0x01000193`
- một bước avalanche theo kiểu MurmurHash có hằng số `0x85EBCA6B`
- target hash có thêm salt trước khi so sánh

Phần FNV-1a 32-bit cơ bản có thể biểu diễn như sau:

```c
uint32_t fnv1a32(const uint8_t *name) {
    uint32_t h = 0x811C9DC5;

    while (*name != 0) {
        h ^= *name++;
        h *= 0x01000193;
    }

    return h;
}
```

Đoạn trên **chỉ mô tả phần FNV-1a**, không phải toàn bộ hàm hash của `log.dll`. Báo cáo công khai không cung cấp đủ pseudocode dạng text để suy ra an toàn toàn bộ thứ tự shift, multiply và cách salt được áp dụng. Khi viết tool khôi phục API, các bước còn lại nên được chép từ routine của đúng sample rồi kiểm tra bằng vài cặp input/output quan sát trong debugger.

### 3.2. Resolver của module Chrysalis

Resolver trong module chính không chỉ là một biến thể `ROR13` chạy từng byte. Theo Rapid7, nó:

- nhận hash của API mục tiêu làm đối số;
- đi từ PEB đến `InMemoryOrderModuleList`;
- bỏ qua executable chính và parse export table của các module còn lại;
- xử lý tên API theo từng block 4 byte;
- dùng nhiều phép rotate, multiply và một pha diffusion cuối;
- có đường fallback qua `GetProcAddress` nếu không tìm được hash.

Tên DLL cũng được dựng lại ở runtime bằng một routine riêng có rotate, XOR có điều kiện và phép toán phụ thuộc vị trí ký tự[^r7-report]. Vì vậy, không nên dùng pseudocode byte-by-byte đơn giản để đại diện cho resolver này. Figure 4 và Figure 5 trong báo cáo Rapid7 phù hợp để định hướng khi reverse, nhưng muốn tạo hash table chính xác vẫn cần lấy biểu thức từ sample cụ thể.

## 4. Cách khôi phục API mà không đoán thuật toán

### 4.1. Xác định đúng resolver

Với `log.dll`, có thể tìm các hằng số FNV-1a rồi kiểm tra xem hàm chứa chúng có duyệt Export Directory hay không. Chỉ tìm `0x811C9DC5` là chưa đủ vì FNV-1a còn được Chrysalis dùng cho mục đích khác, chẳng hạn tạo định danh máy nạn nhân.

Với module chính, nên tìm chuỗi hành vi thay vì một hằng số đơn lẻ:

- truy cập PEB;
- duyệt linked list module;
- kiểm tra chữ ký PE;
- đọc `IMAGE_EXPORT_DIRECTORY`;
- ánh xạ `AddressOfNames`, `AddressOfNameOrdinals` và `AddressOfFunctions`;
- so sánh kết quả trộn với target hash.

### 4.2. Theo dõi calling convention

Trước khi tự động hóa, cần xác định target là x86 hay x64 và xem decompiler đã khôi phục prototype thế nào. Trên Windows x64, bốn integer/pointer argument đầu thường đi qua `RCX`, `RDX`, `R8` và `R9`; không thể mặc định hash luôn nằm trong một lệnh `push` ngay trước `call`.

Tương tự, quét lùi và chọn immediate gần nhất dễ bắt nhầm size, flag hoặc địa chỉ. Data-flow từ argument của resolver đáng tin hơn so với khoảng cách lệnh cố định.

### 4.3. Xác nhận ở runtime

Đặt breakpoint tại entry của resolver để ghi lại target hash và tại các điểm return để lấy địa chỉ API đã resolve. Trên x64, giá trị trả về thường nằm trong `RAX`. Sau đó có thể đối chiếu địa chỉ này với export của module tương ứng trong debugger.

Nếu resolver có nhiều nhánh return hoặc được gọi đồng thời từ nhiều thread, nên ghi lại theo thread và call depth. Việc đọc `[RSP+8]` tại `ret` rồi coi đó là hash không phải giả định an toàn trên Windows x64; vị trí đó phụ thuộc prologue, stack frame và cách đối số được truyền.

### 4.4. Chỉ rename khi đã có bằng chứng

Một script IDA/Ghidra nên lưu ít nhất:

- địa chỉ call site;
- target hash;
- tên module và export khớp;
- cách khớp: static hay runtime;
- trạng thái collision nếu nhiều export có cùng hash.

Nên đặt comment tại call site trước. Chỉ rename wrapper khi hàm đó thực sự chỉ đại diện cho một API. Rename toàn bộ caller dựa trên một lần gọi resolver có thể che mất logic khác trong cùng hàm.

## 5. Ghi chú về C2 và persistence

Rapid7 cho biết cấu hình Chrysalis được mã hóa bằng RC4 với một key hardcode. Sau khi giải mã, cấu hình chứa URL dưới domain `api.skycloudcenter[.]com`; cấu trúc đường dẫn trông giống endpoint chat của DeepSeek. Đây là cách ngụy trang hình thức URL, không có nghĩa lưu lượng đi tới hạ tầng DeepSeek[^r7-report].

Dữ liệu gửi tới C2 tiếp tục được mã hóa RC4 bằng một key hardcode khác và truyền qua HTTPS/port 443. Báo cáo không mô tả cơ chế “rotate key mỗi session”, vì vậy không nên gán đặc tính đó cho mẫu.

Về persistence, Chrysalis thử tạo Windows service và dùng Registry Run key làm phương án dự phòng. Báo cáo cũng ghi nhận mutex `Global\Jdhfv_1.0.1`. Domain `api.wiresguard[.]com` xuất hiện ở các loader Cobalt Strike liên quan mà Rapid7 tìm thấy, không phải C2 chính trong cấu hình Chrysalis.

## 6. IOC đã đối chiếu với Rapid7

Các giá trị dưới đây được lấy từ bảng IOC trong báo cáo Rapid7. Dấu `.` trong domain được thay bằng `[.]` để tránh click nhầm.

### File hashes

| File | SHA-256 |
|---|---|
| `update.exe` | `a511be5164dc1122fb5a7daa3eef9467e43d8458425b15a640235796006590c9` |
| `[NSIS].nsi` | `8ea8b83645fba6e23d48075a0d3fc73ad2ba515b4536710cda4f1f232718f53e` |
| `BluetoothService.exe` | `2da00de67720f5f13b17e9d985fe70f10f153da60c9ab1086fe58f069a156924` |
| `BluetoothService` (encrypted shellcode) | `77bfea78def679aa1117f569a35e8fd1542df21f7e00e27f192c907e61d63a2e` |
| `log.dll` | `3bdc4c0637591533f1d4198a72a33426c01f69bd2e15ceee547866f65e26b7ad` |

### Network indicators

| Vai trò | Indicator |
|---|---|
| Nguồn tải `update.exe` quan sát được | `95.179.213[.]0` |
| C2 trong cấu hình Chrysalis | `api.skycloudcenter[.]com` |
| IP mà domain trên phân giải tới lúc Rapid7 phân tích | `61.4.102[.]97` |
| Hạ tầng loader/Cobalt Strike liên quan | `59.110.7[.]32` |
| Hạ tầng loader/Cobalt Strike liên quan | `124.222.137[.]114` |
| Hạ tầng loader/Cobalt Strike liên quan | `api.wiresguard[.]com` |

IOC có thể được tái sử dụng hoặc hết hiệu lực. Khi hunting, nên kết hợp chúng với quan hệ tiến trình, đường dẫn drop file và hành vi DLL side-loading thay vì chỉ block theo hash hoặc IP.

## 7. Vì sao tôi không giữ các YARA rule cũ?

YARA rule dựa trên byte pattern cần được chạy thử trên mẫu dương tính và một tập file sạch đủ rộng. Nếu chưa có binary để kiểm tra, các pattern cho FNV, RC4 hoặc chuỗi lệnh gọi gián tiếp rất dễ quá rộng hoặc phụ thuộc compiler. Một rule gắn tên Lotus Blossom nhưng chưa được test có thể tạo cảm giác chính xác hơn mức bằng chứng thực tế.

Nếu có mẫu hợp lệ, quy trình phù hợp là:

1. Bắt đầu từ chuỗi hoặc cấu trúc có nguồn gốc rõ ràng trong mẫu.
2. Thêm byte pattern cho routine chỉ sau khi kiểm tra nhiều vị trí và biến thể compiler.
3. Test trên toàn bộ sample liên quan đã có.
4. Test false positive trên các PE sạch, đặc biệt là phần mềm có FNV/RC4 hợp lệ.
5. Ghi rõ phạm vi: sample-specific, family-level hay behavior-oriented.

## 8. Kết luận

Điểm đáng chú ý trong chuỗi này là loader và module chính dùng hai cơ chế phân giải API khác nhau. `log.dll` dùng FNV-1a, một bước avalanche kiểu MurmurHash và target có salt; Chrysalis dùng routine theo block 4 byte cùng logic trộn phức tạp hơn. Cả hai đều có thể phân tích được nếu tách rõ ba phần: cách lấy module, cách duyệt export và cách biến đổi tên API.

Khi viết tool hỗ trợ, phần khó không nằm ở việc tạo một dictionary hash, mà ở chỗ sao chép đúng routine của sample, theo dõi đúng calling convention và xử lý collision. Nếu chưa xác nhận được những điểm đó, comment có kèm mức tin cậy thường hữu ích hơn rename tự động hàng loạt.

---

## References

[^r7-report]: Rapid7 Labs. *The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's Toolkit*. Published 02/02/2026, updated 09/02/2026. [https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/)

[^r7-followup]: Rapid7. *Chrysalis, Notepad++, and Supply Chain Risk: What it Means, and What to Do Next*. 05/02/2026. [https://www.rapid7.com/blog/post/tr-chrysalis-notepad-supply-chain-risk-next-steps/](https://www.rapid7.com/blog/post/tr-chrysalis-notepad-supply-chain-risk-next-steps/)

[^mitre-lbg]: MITRE ATT&CK. *Lotus Blossom (G0030)*. [https://attack.mitre.org/groups/G0030/](https://attack.mitre.org/groups/G0030/)

[^mitre-dynamic-api]: MITRE ATT&CK. *T1027.007 - Dynamic API Resolution*. [https://attack.mitre.org/techniques/T1027/007/](https://attack.mitre.org/techniques/T1027/007/)
