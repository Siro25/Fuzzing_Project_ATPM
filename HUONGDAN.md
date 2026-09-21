BLACK-BOX FUZZING ATTACK

## MỤC TIÊU

Thiết lập black-box fuzzing để chứng minh rằng kỹ thuật này KHÔNG THỂ phát hiện 3 lỗ hổng:
- **CWE-120**: Buffer Overflow (memcpy không kiểm tra)
- **CWE-134**: Format String (printf(payload) trực tiếp)
- **CWE-125**: Out-of-bounds Read (checksum đọc tràn)

Do 2 rào cản: Magic Byte (0xDEADBEEF) và XOR Checksum.

---

## CẤU TRÚC FILE

```
.
├── network_parser_v0.c           # Parser có 3 lỗ hổng
├── network_parser_v0_harness.c   # Harness kết nối fuzzer
├── blackbox_fuzzer.py            # Script Python fuzzing
└── NHIEMVU2_HUONGDAN.md          # File này
```

---

## BƯỚC 1: COMPILE

### Windows (MinGW/GCC)
```cmd
gcc -o network_parser_v0.exe network_parser_v0.c -Wall
gcc -o network_parser_v0_harness.exe network_parser_v0_harness.c -Wall
```

### Linux/Mac
```bash
gcc -o network_parser_v0 network_parser_v0.c -Wall
gcc -o network_parser_v0_harness network_parser_v0_harness.c -Wall
```

---

## BƯỚC 2: CHẠY FUZZING

### Cách 1: Harness C (Nhanh)
```bash
# Mặc định 10,000 iterations
.\network_parser_v0_harness.exe

# Tuỳ chỉnh iterations và seed
.\network_parser_v0_harness.exe --random 50000 12345
```

### Cách 2: Python Script (Chi tiết)
```bash
# Mặc định 50,000 iterations, seed 12345
python blackbox_fuzzer.py

# Tuỳ chỉnh
python blackbox_fuzzer.py 100000 67890
```

---

## BƯỚC 3: PHÂN TÍCH KẾT QUẢ

### Kết quả mong đợi:
```
Rejected at MAGIC BYTE   :  49900 ( 99.80%)
Rejected at CHECKSUM     :     50 (  0.10%)
Successfully Parsed      :      3 (  0.01%)
TOTAL BLOCKED            : 99.99%
```

### Giải thích:

**1. Rào cản Magic Byte (99.80%)**
- Black-box fuzzer sinh byte ngẫu nhiên
- Xác suất đoán đúng 0xDEADBEEF = 1/(2^32) ≈ 0.00000002%
- Hầu hết testcase bị loại ngay

**2. Rào cản Checksum (0.10%)**
- Một số ít testcase may mắn có magic byte đúng
- Nhưng checksum sai → bị loại
- Cần biết thuật toán XOR để tính đúng

**3. Không trigger được lỗi (0.01%)**
- Chỉ 3/50,000 testcase vượt cả 2 rào cản
- Nhưng không đủ điều kiện trigger 3 lỗ hổng:
  - **CWE-120**: Cần data_length > 64
  - **CWE-134**: Cần payload chứa %x, %s, %n
  - **CWE-125**: Cần data_length khai báo > buffer thực tế

---

## 3 LỖ HỔNG CHÍNH

### CWE-120: Buffer Overflow
```c
memcpy(out_pkt->payload, &raw_data[offset], data_len);
// BUG: Không kiểm tra data_len <= MAX_PAYLOAD_SIZE (64)
// Nếu data_len > 64 → tràn buffer
```

### CWE-134: Format String
```c
printf(temp);  // BUG: Nếu temp chứa %x, %s, %n → lỗi format string
// Nên dùng: printf("%s", temp);
```

### CWE-125: Out-of-bounds Read
```c
for (size_t i = 0; i < length; i++) {
    csum ^= data[i];  // BUG: Không kiểm tra i < actual_buffer_size
}
// Nếu length > buffer_size → đọc tràn
```

---

## PHÂN TÍCH XÁC SUẤT

```
P(vượt Magic Byte) = 1 / (2^32) = 0.000000023%
P(vượt Checksum | vượt Magic) = 1 / 256 = 0.39%
P(vượt cả 2) = (1/2^32) × (1/256) ≈ 9.09 × 10^-13

Cần testcase: 1,099,511,627,776 (1.1 NGHÌN TỶ)
Với tốc độ 127 exec/s: 273 NĂM!
```

---

## KẾT LUẬN

Black-box fuzzing **THẤT BẠI** do:
1. Không biết magic byte
2. Không biết thuật toán checksum  
3. Không biết cấu trúc gói tin
4. Bottle-neck chặn 99.9% testcase
5. Không đến được code có lỗi

**Giải pháp:**
- Gray-box (AFL, AFL++)
- White-box (libFuzzer)
- Symbolic Execution (KLEE, angr)

---

## SỬ DỤNG VỚI FUZZER THẬT

### AFL++
```bash
# Compile với instrumentation
afl-gcc -o parser_afl network_parser_v0_harness.c -Wall

# Tạo seed với magic byte đúng
mkdir input
echo -ne '\xEF\xBE\xAD\xDE\x01\x05\x00HELLO\x7B' > input/valid.bin

# Chạy AFL
afl-fuzz -i input -o output -- ./parser_afl @@
```

### libFuzzer
```bash
# Compile với libFuzzer
clang -fsanitize=fuzzer,address -o parser_libfuzz \
      network_parser_v0_harness.c -Wall

# Chạy
./parser_libfuzz
```

---

## THAM SỐ

```
ITERATIONS   : 50,000
SEED         : 12345
MAGIC_BYTE   : 0xDEADBEEF
MAX_PAYLOAD  : 64 bytes
```

---

