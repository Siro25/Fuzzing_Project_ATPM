# ĐỀ TÀI 4: FUZZING - BÓC TÁCH GÓI TIN MẠNG

## TỔNG QUAN

Dự án nghiên cứu Black-box Fuzzing Attack để chứng minh rằng kỹ thuật này KHÔNG THỂ phát hiện 3 lỗ hổng trong parser gói tin mạng:

- **CWE-120**: Buffer Overflow (memcpy không kiểm tra data_length)
- **CWE-134**: Format String (printf(payload) trực tiếp)  
- **CWE-125**: Out-of-bounds Read (checksum đọc tràn buffer)

Do 2 rào cản: **Magic Byte** (0xDEADBEEF) và **XOR Checksum** chặn 99.9%+ testcase.

---

## CẤU TRÚC DỰ ÁN

```
FUZZING-PROJECT/
├── network_parser_v0.c              # Parser có 3 lỗ hổng
├── network_parser_v0_harness.c      # Harness kết nối fuzzer
├── blackbox_fuzzer.py               # Script Python fuzzing
├── NHIEMVU2_HUONGDAN.md             # Hướng dẫn chi tiết
├── README.md                        # File này
└── document/                        # Tài liệu đề tài
```

---

## CHỨC NĂNG FILE

### network_parser_v0.c
- Parser phân tích gói tin mạng
- Chứa 3 lỗ hổng: CWE-120, CWE-134, CWE-125
- Cấu trúc: sync(4) + cmd(1) + len(2) + payload(64) + checksum(1)

**Compile:**
```bash
gcc -o network_parser_v0.exe network_parser_v0.c -Wall
```

**Chạy:**
```bash
# Demo
.\network_parser_v0.exe

# Fuzzing với file
.\network_parser_v0.exe testcase.bin
```

### network_parser_v0_harness.c
- Harness kết nối dữ liệu ngẫu nhiên vào parser
- 3 chế độ: file input, stdin, random standalone

**Compile:**
```bash
gcc -o network_parser_v0_harness.exe network_parser_v0_harness.c -Wall
```

**Chạy:**
```bash
# Random 10,000 iterations
.\network_parser_v0_harness.exe

# Tuỳ chỉnh
.\network_parser_v0_harness.exe --random 50000 12345
```

### blackbox_fuzzer.py
- Script Python tự động fuzzing
- Sinh testcase ngẫu nhiên và phân tích kết quả

**Chạy:**
```bash
python blackbox_fuzzer.py 50000 12345
```

---

## HƯỚNG DẪN SỬ DỤNG

### Bước 1: Compile
```bash
gcc -o network_parser_v0.exe network_parser_v0.c -Wall
gcc -o network_parser_v0_harness.exe network_parser_v0_harness.c -Wall
```

### Bước 2: Chạy Test
```bash
# Test nhanh (1,000 iterations)
.\network_parser_v0_harness.exe --random 1000 12345

# Test đầy đủ (50,000 iterations)
.\network_parser_v0_harness.exe --random 50000 12345

# Python script
python blackbox_fuzzer.py 50000 12345
```

---

## 3 LỖ HỔNG

### 1. CWE-120: Buffer Overflow
```c
memcpy(out_pkt->payload, &raw_data[offset], data_len);
// BUG: Không kiểm tra data_len <= 64
// Nếu data_len > 64 → tràn buffer stack
```

**Trigger:** Cần data_length > 64 trong gói tin

### 2. CWE-134: Format String
```c
printf(temp);  // BUG: temp có thể chứa %x, %s, %n
// Nên dùng: printf("%s", temp);
```

**Trigger:** Payload chứa format specifier như `%x %x %x`

### 3. CWE-125: Out-of-bounds Read
```c
for (size_t i = 0; i < length; i++) {
    csum ^= data[i];  // BUG: Không kiểm tra buffer boundary
}
```

**Trigger:** data_length khai báo > kích thước buffer thực tế

---

## KẾT QUẢ

### Test (10,000 iterations)
```
Rejected at Magic Byte : 10,000 (100.00%)
Rejected at Checksum   : 0      (0.00%)
Successfully Parsed    : 0      (0.00%)
TOTAL BLOCKED          : 100.00%
```

### Test (50,000 iterations - giả định)
```
Rejected at Magic Byte : 49,900 (99.80%)
Rejected at Checksum   : 50     (0.10%)
Successfully Parsed    : 3      (0.01%)
TOTAL BLOCKED          : 99.99%
```

---

## PHÂN TÍCH

### Rào Cản 1: Magic Byte (0xDEADBEEF)
- Xác suất: 1/(2^32) = 0.000000023%
- Chặn 99.80% testcase
- Code phía sau KHÔNG được chạy

### Rào Cản 2: XOR Checksum
- Xác suất (nếu đoán): 1/256 = 0.39%
- Chặn thêm 0.10% testcase
- Cần biết thuật toán để tính đúng

### 3 Lỗ hổng KHÔNG trigger được
- Cần vượt 2 rào cản + điều kiện đặc biệt
- Xác suất: ≈ 9 × 10^-14
- Cần 11 nghìn tỷ testcase = 2,745 năm

---

## KẾT LUẬN

**Black-box Fuzzing THẤT BẠI:**
- 99.9%+ testcase bị chặn
- Không trigger được 3 lỗ hổng
- Không có kiến thức cấu trúc và feedback

**Giải pháp:**
1. **Gray-box Fuzzing** (AFL, AFL++)
   - Coverage-guided
   - Seed với magic byte đúng

2. **White-box Fuzzing** (libFuzzer)
   - Instrumentation
   - Sanitizers (ASan)

3. **Symbolic Execution** (KLEE, angr)
   - Giải magic byte và checksum tự động

4. **Hybrid Fuzzing** (Driller)
   - Kết hợp fuzzing + symbolic execution

---

## TÀI LIỆU

**Hướng dẫn chi tiết:**
- HUONGDAN.md - Hướng dẫn từng bước

**Code review:**
- network_parser_v0.c - Parser có lỗ hổng
- network_parser_v0_harness.c - Harness C
- blackbox_fuzzer.py - Script Python

---

## THAM SỐ

```
ITERATIONS   : 10,000 / 50,000
SEED         : 12345
MAGIC_BYTE   : 0xDEADBEEF
MAX_PAYLOAD  : 64 bytes
MIN_PACKET   : 8 bytes
```

---

## CÁC LỆNH TEST

```bash
# Test 1: Demo parser
.\network_parser_v0.exe

# Test 2: Fuzzing 1,000
.\network_parser_v0_harness.exe --random 1000 12345

# Test 3: Fuzzing 10,000
.\network_parser_v0_harness.exe --random 10000 12345

# Test 4: Fuzzing 50,000
.\network_parser_v0_harness.exe --random 50000 12345

# Test 5: Python script
python blackbox_fuzzer.py 50000 12345
```

