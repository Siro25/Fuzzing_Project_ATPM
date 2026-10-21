# dynamic_loop_crash – Crash/Hang từ vòng lặp gán dữ liệu liên tục

Thư mục này lưu **tự động** bởi `run_dynamic_fuzz.py` khi chạy với
`--mode loop`, `--mode arith`, `--mode dict`, hoặc `--mode all`.

## Cấu trúc

```
dynamic_loop_crash/
├── README.md              ← file này
├── all_crashes.jsonl      ← master log: MỌI crash/hang từ mọi run (append-only)
└── run_YYYYMMDD_HHmmss_µs/
    ├── r01_i0042_crash.bin   ← byte đầu vào gây crash (có thể reproduce)
    ├── r01_i0042_crash.json  ← metadata đầy đủ (state, mode, hex, output...)
    └── ...
```

## Cách dùng `analyze_logs.py`

```bash
# Phân tích tất cả crash trong thư mục này
python ch4_dynafuzz/analyze_logs.py

# Chỉ phân tích 1 run cụ thể
python ch4_dynafuzz/analyze_logs.py --run run_20261019_234846_233690

# Xuất báo cáo HTML
python ch4_dynafuzz/analyze_logs.py --report html
```

## Các trường hợp ngoại lệ cần chú ý

| Loại | Dấu hiệu | CWE liên quan |
|------|-----------|---------------|
| Format String | output chứa địa chỉ hex / stack leak | CWE-134 |
| Buffer Overflow | exit code ≠ 0,1 hoặc crash khi size > 64 | CWE-120 |
| Out-of-bounds Read | crash với state=`length_mismatch` + large declared length | CWE-125 |
| Loop Hang | kind=`hang` sau nhiều iteration carry | N/A |
| Unexpected exit | exit_code ∉ {0,1,None} | N/A |
