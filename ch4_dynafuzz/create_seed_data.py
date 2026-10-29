#!/usr/bin/env python3
"""
Tạo file seed data dựa trên cấu trúc gói tin và hàm seeds() từ run_dynamic_fuzz.py.

Cách dùng:
    python ch4_dynafuzz/create_seed_data.py
    python ch4_dynafuzz/create_seed_data.py --all   # Xuất toàn bộ 16 seed vào thư mục seeds/
"""

import argparse
from pathlib import Path
import struct
import sys

# Import logic từ run_dynamic_fuzz
CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR.parent))

from ch4_dynafuzz.run_dynamic_fuzz import MAGIC, packet, seeds, modeled_state


def main():
    parser = argparse.ArgumentParser(description="Tạo file seed data từ run_dynamic_fuzz.py")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=CURRENT_DIR / "seed_data.bin",
        help="Đường dẫn file seed data cần tạo (mặc định: ch4_dynafuzz/seed_data.bin)",
    )
    parser.add_argument(
        "--payload", "-p",
        type=str,
        default="HELLO_FUZZING_SEED",
        help="Nội dung payload dạng text cho seed mặc định",
    )
    parser.add_argument(
        "--command", "-c",
        type=int,
        default=1,
        help="Command ID (0-255, mặc định: 1)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Xuất toàn bộ 16 mẫu seed trong hàm seeds() ra thư mục seeds/",
    )
    args = parser.parse_args()

    # 1. Tạo file seed data chính (chuẩn hợp lệ)
    seed_bytes = packet(args.payload.encode("utf-8"), command=args.command, valid_checksum=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(seed_bytes)

    state = modeled_state(seed_bytes)
    print(f"[+] Đã tạo file seed data: {args.output}")
    print(f"    - Kích thước : {len(seed_bytes)} bytes")
    print(f"    - Trạng thái : {state}")
    print(f"    - Hex dump   : {seed_bytes.hex()}")

    # 2. Nếu có cờ --all, xuất toàn bộ corpus của run_dynamic_fuzz
    if args.all:
        seeds_dir = CURRENT_DIR / "seeds"
        seeds_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[+] Đang xuất 16 seeds vào thư mục: {seeds_dir}")
        for idx, (name, data) in enumerate(seeds(), start=1):
            seed_file = seeds_dir / f"{idx:02d}_{name}.bin"
            seed_file.write_bytes(data)
            s_state = modeled_state(data)
            print(f"  [{idx:02d}] {seed_file.name:<25} ({len(data):3d} bytes) -> {s_state}")


if __name__ == "__main__":
    main()
