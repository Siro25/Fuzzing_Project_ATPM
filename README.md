# ĐỀ TÀI 4: FUZZING – BÓC TÁCH GÓI TIN MẠNG

---

## TỔNG QUAN

Dự án so sánh hiệu năng **Black-box Fuzzing** và **White-box Fuzzing (Z3 SMT Solver)** trên một trình phân tích gói tin mạng tự xây dựng, chứa 3 lỗ hổng được cài cắm có chủ đích.

| # | CWE | Mô tả | Vị trí | Điều kiện kích hoạt |
|---|---|---|---|---|
| 1 | **CWE-120** | Buffer Overflow – `memcpy` không kiểm tra `data_length` | `network_parser_v0.c:151` | `data_length > 64`, checksum hợp lệ |
| 2 | **CWE-134** | Format String – `printf(temp)` không dùng format string | `network_parser_v0.c:85` | Payload chứa `%x/%n`, checksum sai |
| 3 | **CWE-125** | Out-of-bounds Read – vòng lặp checksum đọc tràn | `network_parser_v0.c:46` | `data_length` khai báo > buffer thực tế |

Hai rào cản bảo vệ ngăn Black-box tiếp cận lỗi: **Magic Byte** (`0xDEADBEEF`) và **XOR Checksum**.

---

## CẤU TRÚC DỰ ÁN

```
ATPM/
├── network_parser_v0.c            # Parser có 3 lỗ hổng (VULNERABLE)
├── network_parser_v0_harness.c    # Harness kết nối fuzzer vào parser
├── network_parser_v1.c            # Bản vá an toàn (PATCHED – 0 ASan findings)
│
├── blackbox_fuzzer.py             # Black-box fuzzer (50k iterations)
├── whitebox_z3_fuzzer.py          # White-box fuzzer dùng Z3 SMT Solver
│
├── z3_testcases/                  # Testcase do Z3 tạo ra
│   ├── tc_cwe120_overflow.bin     #   136 bytes – trigger CWE-120 (checksum=0xE3)
│   ├── tc_cwe134_formatstr.bin    #   40  bytes – trigger CWE-134 (%x.%x.%n payload)
│   └── tc_cwe125_oobread.bin      #   208 bytes – trigger CWE-125 (khai báo 200, thực 200)
│
├── HUONGDAN.md                    # Hướng dẫn chi tiết từng bước
├── README.md                      # File này
└── document/                      # Tài liệu ý tưởng đề tài
```

---

## NHANH: COMPILE & CHẠY

### Compile tất cả (Windows / MinGW)
```bash
gcc -o network_parser_v0.exe network_parser_v0.c -Wall
gcc -o network_parser_v1.exe network_parser_v1.c -Wall
gcc -o network_parser_v0_harness.exe network_parser_v0_harness.c -Wall
```

### Compile với ASan (Linux – để kiểm tra lỗi)
```bash
gcc -fsanitize=address -o parser_v0_asan network_parser_v0.c -Wall
gcc -fsanitize=address -o parser_v1_asan network_parser_v1.c -Wall
```

### Chạy Black-box Fuzzer
```bash
python blackbox_fuzzer.py 50000 12345
```

### Chạy White-box Z3 Fuzzer
```bash
pip install z3-solver        # Cài Z3 nếu chưa có
python whitebox_z3_fuzzer.py # Tạo 3 testcase, in báo cáo so sánh
```

### Kiểm tra testcase trên v0 (trigger lỗi)
```bash
# Windows
.\network_parser_v0.exe z3_testcases\tc_cwe120_overflow.bin

# Linux với ASan (thấy log lỗi đỏ)
./parser_v0_asan z3_testcases/tc_cwe120_overflow.bin
```

### Kiểm tra bản vá v1 (0 finding)
```bash
.\network_parser_v1.exe z3_testcases\tc_cwe120_overflow.bin
# Kết quả: [LOI-v1] Payload qua lon: 128 bytes (max 64). TU CHOI.
```

---

## 3 LỖ HỔNG – PHÂN TÍCH CHI TIẾT

### CWE-120: Buffer Overflow (`network_parser_v0.c:151`)

**Luồng kích hoạt:** Sync đúng → Checksum hợp lệ → `data_length > 64` → `memcpy` tràn

```c
// v0 - LỖI: không kiểm tra data_len <= 64
memcpy(out_pkt->payload, &raw_data[offset], data_len);
// out_pkt->payload chỉ có 64 byte, data_len = 128 → ghi tràn 64 byte vào stack!

// v1 - AN TOÀN: từ chối tận gốc trước khi memcpy
if (data_len > MAX_PAYLOAD_SIZE) return ERR_PAYLOAD_TOO_LARGE;
memcpy(out_pkt->payload, &raw_data[offset], data_len);
```

**Testcase Z3:** `tc_cwe120_overflow.bin` – 136 bytes, data_length=128, checksum=0xE3

---

### CWE-134: Format String (`network_parser_v0.c:85`)

**Luồng kích hoạt:** Sync đúng → `data_length ≤ 64` → checksum SAI → `log_error_packet()` → `printf(temp)`

```c
// v0 - LỖI: nếu temp = "%x%x%n" → đọc/ghi stack tùy ý
printf(temp);

// v1 - AN TOÀN: temp luôn được coi là chuỗi ký tự thường
printf("%s", temp);
```

**Testcase Z3:** `tc_cwe134_formatstr.bin` – 40 bytes, payload=`%x.%x.%x.%x.%n.%s.%p.%p.%p.%p.%p`, checksum sai 1 đơn vị

> **Lưu ý:** CWE-134 cũng được trigger ở nhánh `ERR_LENGTH_MISMATCH` (dòng 140-142 v0) khi `data_length > raw_length - offset - 1` và `data_len < 64`. Đây là đường trigger thứ hai ít được chú ý.

---

### CWE-125: Out-of-bounds Read (`network_parser_v0.c:46`)

**Luồng kích hoạt (v0):** Sync đúng → `data_length` lớn nhưng raw buffer đủ → `memcpy` OK → `calculate_checksum(raw_data, offset)` với `offset = data_len + 7` có thể vượt ranh giới heap

```c
// v0 - LỖI: length có thể > kích thước buffer thực
for (size_t i = 0; i < length; i++) { csum ^= data[i]; }

// v1 - AN TOÀN: điều kiện kép ngăn đọc tràn
for (size_t i = 0; i < length && i < max_len; i++) { csum ^= data[i]; }
```

**Testcase Z3:** `tc_cwe125_oobread.bin` – 208 bytes, data_length=200, checksum hợp lệ để vượt qua CWE-120 check và đến được `calculate_checksum`

---

## CÁC TRƯỜNG HỢP BIÊN (EDGE CASES)

Ngoài 3 lỗ hổng chính, các trường hợp sau cũng được kiểm tra:

| Trường hợp | Input | Hành vi v0 | Hành vi v1 |
|---|---|---|---|
| **File rỗng** | 0 bytes | `ERR_TOO_SHORT` | `ERR_TOO_SHORT` |
| **File 1 byte** | 1 byte | `ERR_TOO_SHORT` | `ERR_TOO_SHORT` |
| **Payload rỗng** | `data_length = 0` | Parse OK | Parse OK |
| **Payload đúng ranh giới** | `data_length = 64` | Parse OK | Parse OK |
| **Payload qua ranh giới 1 byte** | `data_length = 65` | **CWE-120 xảy ra** | Từ chối |
| **data_length = MAX (65535)** | `data_length = 65535` | `ERR_LENGTH_MISMATCH` | `ERR_PAYLOAD_TOO_LARGE` |
| **Con trỏ NULL** | `raw_data = NULL` | `ERR_NULL_INPUT` | `ERR_NULL_INPUT` |
| **Sync sai** | Byte đầu != 0xDEADBEEF | `ERR_SYNC_MISMATCH` | `ERR_SYNC_MISMATCH` |
| **Checksum sai** | Checksum không khớp | `ERR_CHECKSUM_INVALID` + CWE-134 | `ERR_CHECKSUM_INVALID` (an toàn) |

---

## KẾT QUẢ SO SÁNH

### Black-box Fuzzing (50.000 iterations)
```
Rejected at MAGIC BYTE  : 49,900  (99.80%)
Rejected at CHECKSUM    :     50  ( 0.10%)
Rejected (Other)        :     47  ( 0.09%)
Successfully Parsed     :      3  ( 0.01%)  <- không trigger được lỗi
─────────────────────────────────────────────
TOTAL BLOCKED           : 99.99%
Thời gian thực thi      : ~393 giây
Lỗi CWE kích hoạt       : 0 / 3
```

### White-box Z3 Fuzzing (đo thực tế)
```
Tổng lần gọi Z3         : 3
Tổng thời gian Z3       : 62.094 ms
Tổng thời gian chạy     : 0.072 giây
Testcase hữu ích tạo ra : 3 / 3
Lỗi CWE kích hoạt       : 3 / 3   <- 100% thành công
```

| Tiêu chí | Black-box | White-box (Z3) |
|---|---|---|
| Số lần thử | 50.000 | **3** |
| Thời gian | 393 giây | **0,072 giây** |
| Vượt rào cản | ~0,01% (tình cờ) | **100%** (Z3 giải) |
| CWE kích hoạt | **0/3** | **3/3** |
| Tốc độ cải thiện | — | **≈ 5.460× nhanh hơn** |

---

## PHÂN TÍCH XÁC SUẤT

```
P(vượt Magic Byte)         = 1 / 2^32  ≈ 2,33 × 10^-8 %
P(vượt Checksum | vượt MB) = 1 / 256   ≈ 0,39%
P(vượt cả 2)               ≈ 9,09 × 10^-13 %

Cần trung bình : ~1,1 nghìn tỷ testcase
Tốc độ thực tế : ~127 exec/s
Thời gian dự kiến: ≈ 273 NĂM
```

Z3 giải bài toán XOR (tuyến tính trên GF(2)) trong **< 2 mili-giây** — không đoán mò, giải phương trình trực tiếp.

---

## BẢN VÁ

File [`network_parser_v1.c`](./network_parser_v1.c) vá cả 3 lỗ hổng. Kiểm chứng:

```
Testcase                    | Parser v0              | Parser v1
─────────────────────────────────────────────────────────────────
tc_cwe120_overflow.bin      | PARSE OK (tràn bộ đệm) | TU CHOI (-6)
tc_cwe134_formatstr.bin     | %x được thực thi       | %x in nguyên văn
tc_cwe125_oobread.bin       | PARSE OK (đọc tràn)    | TU CHOI (-6)

ASan (Linux):
  parser_v0_asan -> SUMMARY: AddressSanitizer: stack-buffer-overflow
  parser_v1_asan -> (không có dòng lỗi) – 0 findings
```

---

## TÀI LIỆU THAM KHẢO

- **HUONGDAN.md** – Hướng dẫn từng bước chi tiết
- **whitebox_z3_fuzzer.py** – Code có chú thích đầy đủ cho Z3 logic
- **network_parser_v1.c** – Code có chú thích Before/After cho từng fix
- [CWE-120](https://cwe.mitre.org/data/definitions/120.html) – Buffer Copy without Checking Size of Input
- [CWE-134](https://cwe.mitre.org/data/definitions/134.html) – Use of Externally-Controlled Format String
- [CWE-125](https://cwe.mitre.org/data/definitions/125.html) – Out-of-bounds Read
- [Z3 Solver (Microsoft Research)](https://github.com/Z3Prover/z3)
