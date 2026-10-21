# Dynamic fuzzing logs

## Chạy fuzzer

```bash
# Chế độ đầy đủ (tất cả mutation mode): 5 rounds × 150 cases
python ch4_dynafuzz/run_dynamic_fuzz.py --rounds 5 --iterations 150 --mode all

# Chế độ vòng lặp lặp lại liên tục (kiểm tra crash tích lũy):
python ch4_dynafuzz/run_dynamic_fuzz.py --rounds 3 --iterations 200 --mode loop

# Arithmetic mutation (bài 08 – ±1/huge cho length field):
python ch4_dynafuzz/run_dynamic_fuzz.py --mode arith

# Dictionary-guided (bài 09 – token đặc biệt %n, %x, BEGIN...):
python ch4_dynafuzz/run_dynamic_fuzz.py --mode dict
```

## Cấu trúc thư mục

```
logs/
├── README.md
├── dynamic_loop_crash/          ← crash/hang riêng từ loop/arith/dict/all
│   ├── README.md
│   ├── all_crashes.jsonl        ← master log (append-only)
│   └── run_YYYYMMDD_HHmmss/
│       ├── r01_i042_crash.bin
│       └── r01_i042_crash.json
└── run_YYYYMMDD_HHmmss/         ← mỗi lần chạy
    ├── summary.json             ← tổng hợp: state coverage, gcov, symbolic cost
    ├── cases.jsonl              ← mọi case (hex + output)
    ├── compile.log
    ├── coverage/
    │   ├── gcov_output.txt
    │   └── network_parser_v0.c.gcov
    └── findings/                ← input gây crash/hang
```

## Phân tích log tìm ngoại lệ

```bash
# Báo cáo text (tất cả run)
python ch4_dynafuzz/analyze_logs.py

# Báo cáo HTML
python ch4_dynafuzz/analyze_logs.py --report html --out report.html

# Chỉ 1 run cụ thể
python ch4_dynafuzz/analyze_logs.py --run run_20261019_234846_233690
```

## Trường hợp ngoại lệ phát hiện

| Tag | Ý nghĩa | CWE |
|-----|---------|-----|
| `crash_nonzero` | exit code ≠ 0,1 | CWE-120/125 |
| `hang` | timeout | N/A |
| `format_string_hit` | hex leak trong output | CWE-134 |
| `overflow_hit` | size>72 + crash | CWE-120 |
| `oob_read_hit` | length_mismatch + crash | CWE-125 |
| `loop_carry_crash` | crash từ vòng lặp tích lũy | N/A |
| `runner_exception` | lỗi OS spawn | N/A |
| `unexpected_state` | state không xác định | N/A |

## Trường summary.json mới

- `mutation_mode`: chế độ chạy (standard/arith/dict/loop/all)
- `symbolic_cost`: ước lượng chi phí symbolic execution (bài 10)
- `source_coverage`: gcov lines/branches (đã fix path bug)

