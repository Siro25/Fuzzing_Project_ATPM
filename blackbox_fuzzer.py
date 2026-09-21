#!/usr/bin/env python3
"""
Đề tài 4: Black-box Fuzzing Script
File: blackbox_fuzzer.py
Sinh testcase ngẫu nhiên và chạy parser
"""

import os
import sys
import random
import struct
import subprocess
import time
from pathlib import Path

SYNC_WORD = 0xDEADBEEF
MAX_PAYLOAD_SIZE = 64
TOTAL_ITERATIONS = 50000
SEED = 12345
FUZZ_DIR = "fuzz_testcases"
PARSER_EXEC = "network_parser_v0.exe"

stats = {
    'total': 0,
    'rejected_sync': 0,
    'rejected_checksum': 0,
    'rejected_other': 0,
    'success_parsed': 0,
}

def calculate_checksum(data: bytes) -> int:
    """Tính XOR checksum"""
    csum = 0
    for byte in data:
        csum ^= byte
    return csum & 0xFF

def generate_random_packet() -> bytes:
    """
    Sinh gói tin hoàn toàn ngẫu nhiên (black-box).
    KHÔNG biết magic byte, KHÔNG biết checksum.
    """
    size = random.randint(0, 200)
    return bytes([random.randint(0, 255) for _ in range(size)])

def generate_valid_packet(cmd_id: int, payload: bytes) -> bytes:
    """Sinh gói tin HỢP LỆ (chỉ để so sánh)"""
    payload_len = len(payload)
    
    packet = struct.pack('<I', SYNC_WORD)
    packet += struct.pack('B', cmd_id)
    packet += struct.pack('<H', payload_len)
    packet += payload
    
    csum = calculate_checksum(packet)
    packet += struct.pack('B', csum)
    
    return packet

def run_fuzzer():
    """Thực hiện black-box fuzzing"""
    print("=" * 70)
    print("BLACK-BOX FUZZING ATTACK")
    print("=" * 70)
    print(f"Iterations  : {TOTAL_ITERATIONS}")
    print(f"Seed        : {SEED}")
    print(f"Parser      : {PARSER_EXEC}")
    print("=" * 70)
    print()
    
    random.seed(SEED)
    Path(FUZZ_DIR).mkdir(exist_ok=True)
    
    if not Path(PARSER_EXEC).exists():
        print(f"[ERROR] Parser khong tim thay: {PARSER_EXEC}")
        print("Compile truoc: gcc -o network_parser_v0.exe network_parser_v0.c")
        sys.exit(1)
    
    start_time = time.time()
    print("[INFO] Bat dau fuzzing...\n")
    
    for i in range(TOTAL_ITERATIONS):
        stats['total'] += 1
        
        testcase = generate_random_packet()
        testcase_file = os.path.join(FUZZ_DIR, f"testcase_{i}.bin")
        
        with open(testcase_file, 'wb') as f:
            f.write(testcase)
        
        try:
            result = subprocess.run(
                [PARSER_EXEC, testcase_file],
                capture_output=True,
                text=True,
                timeout=1
            )
            
            output = result.stdout + result.stderr
            
            if "Sync Word khong khop" in output or "Du lieu qua ngan" in output:
                stats['rejected_sync'] += 1
            elif "Checksum khong hop le" in output:
                stats['rejected_checksum'] += 1
            elif "Phan tich thanh cong" in output:
                stats['success_parsed'] += 1
            else:
                stats['rejected_other'] += 1
                
        except:
            stats['rejected_other'] += 1
        
        if (i + 1) % 1000 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            print(f"  Progress: {i+1}/{TOTAL_ITERATIONS} "
                  f"({rate:.1f} exec/s) - "
                  f"Sync: {stats['rejected_sync']}, "
                  f"Checksum: {stats['rejected_checksum']}")
    
    elapsed = time.time() - start_time
    print_report(elapsed)
    cleanup()

def print_report(elapsed_time: float):
    """In báo cáo kết quả"""
    print()
    print("=" * 70)
    print("BLACK-BOX FUZZING REPORT")
    print("=" * 70)
    print()
    print(f"Seed                 : {SEED}")
    print(f"Total Iterations     : {stats['total']}")
    print(f"Execution Time       : {elapsed_time:.2f}s")
    print(f"Execution Rate       : {stats['total']/elapsed_time:.1f} exec/s")
    print()
    print("-" * 70)
    print("BARRIER ANALYSIS")
    print("-" * 70)
    
    total = stats['total']
    sync_pct = (stats['rejected_sync'] / total) * 100
    checksum_pct = (stats['rejected_checksum'] / total) * 100
    other_pct = (stats['rejected_other'] / total) * 100
    success_pct = (stats['success_parsed'] / total) * 100
    
    print(f"Rejected at MAGIC BYTE   : {stats['rejected_sync']:6d} ({sync_pct:6.2f}%)")
    print(f"Rejected at CHECKSUM     : {stats['rejected_checksum']:6d} ({checksum_pct:6.2f}%)")
    print(f"Rejected (Other)         : {stats['rejected_other']:6d} ({other_pct:6.2f}%)")
    print(f"Successfully Parsed      : {stats['success_parsed']:6d} ({success_pct:6.2f}%)")
    print()
    
    blocked_pct = sync_pct + checksum_pct + other_pct
    print(f"TOTAL BLOCKED            : {blocked_pct:.2f}%")
    print()
    print("-" * 70)
    print("CONCLUSION")
    print("-" * 70)
    print()
    print(f"Black-box fuzzing bi chan {blocked_pct:.2f}% boi 2 rao can:")
    print("  1. MAGIC BYTE (0xDEADBEEF) - Can doan dung 4 byte (1/2^32)")
    print("  2. XOR CHECKSUM           - Can tinh toan chinh xac")
    print()
    print(f"Chi {success_pct:.3f}% testcase vuot qua duoc ca 2 rao can.")
    print()
    print("=> Black-box fuzzer KHONG THE kich hoat loi:")
    print("   - CWE-120: Buffer Overflow")
    print("   - CWE-134: Format String")
    print("   - CWE-125: Out-of-bounds Read")
    print()
    print("=" * 70)

def cleanup():
    """Xóa testcases"""
    print("[INFO] Don dep testcases...")
    try:
        import shutil
        shutil.rmtree(FUZZ_DIR)
        print(f"[OK] Da xoa thu muc {FUZZ_DIR}")
    except Exception as e:
        print(f"[WARNING] Khong xoa duoc: {e}")

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] in ["--help", "-h"]:
            print("Usage: python blackbox_fuzzer.py [iterations] [seed]")
            print()
            print("Example:")
            print("  python blackbox_fuzzer.py 100000 67890")
            sys.exit(0)
        
        global TOTAL_ITERATIONS, SEED
        if len(sys.argv) > 1:
            TOTAL_ITERATIONS = int(sys.argv[1])
        if len(sys.argv) > 2:
            SEED = int(sys.argv[2])
    
    run_fuzzer()

if __name__ == "__main__":
    main()
