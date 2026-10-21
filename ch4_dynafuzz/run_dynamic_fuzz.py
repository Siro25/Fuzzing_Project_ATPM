"""Repeat packet assignments against the real C parser and retain evidence.

Example: python ch4_dynafuzz/run_dynamic_fuzz.py --rounds 3 --iterations 100

New branches added
------------------
* ``--mode loop``   : Lặp lại quá trình gán dữ liệu liên tục trên CÙNG seed
                      (kiểm tra crash/hang qua vòng lặp tích lũy trạng thái).
* ``--mode dict``   : Dictionary-guided mutation (từ bài 09): ưu tiên token đặc biệt
                      (%x, %s, %n, BEGIN, END, …) để tăng P(format-string hit).
* ``--mode arith``  : Arithmetic mutation (từ bài 08): ±1 / huge cho trường length,
                      bit-flip tự do cho payload.
* ``--mode all``    : Kết hợp tất cả (mặc định).

Coverage
--------
gcov được gọi đúng với tên object file gốc (network_parser_v0.c) để
sinh đúng tên .gcno/.gcda; symbolic cost của cây nhánh cũng được log.
"""

import argparse
import sys

# Đảm bảo stdout UTF-8 trên Windows (tránh UnicodeEncodeError với CP1252)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
LOG_ROOT = Path(__file__).resolve().parent / "logs"
# ── Thư mục riêng lưu crash/hang từ vòng lặp lặp lại liên tục ──────────────
LOOP_CRASH_DIR = LOG_ROOT / "dynamic_loop_crash"

MAGIC = struct.pack("<I", 0xDEADBEEF)
STATES = {
    "empty_file", "too_short", "sync_mismatch", "length_mismatch",
    "checksum_invalid", "parse_ok", "oversized_payload",
}

# ── Từ bài 09: dictionary token đặc biệt ─────────────────────────────────────
DICT_TOKENS: list[bytes] = [
    b"%x", b"%s", b"%n", b"%d", b"%p", b"%%",
    b"BEGIN", b"END", b"EXEC", b"DROP",
    b"\x00" * 4,          # null flood
    b"\xff" * 4,          # 0xFF flood
    b"A" * 64,            # boundary fill
    b"\xde\xad\xbe\xef",  # magic đảo ngược
]

# ── Symbolic cost (từ bài 10) ─────────────────────────────────────────────────
N_INDEPENDENT_BRANCHES = 7   # 7 trạng thái modeled_state → O(n) = 7 lần check
N_NESTED_DEPTH = 5           # độ sâu if-else lồng nhau trong parser → O(2^5)=32


def packet(payload=b"", command=1, declared=None, valid_checksum=True):
    length = len(payload) if declared is None else declared
    body = MAGIC + bytes([command]) + struct.pack("<H", length) + payload
    checksum = 0
    for value in body:
        checksum ^= value
    return body + bytes([checksum if valid_checksum else checksum ^ 1])


def seeds():
    return [
        ("empty",           b""),
        ("short",           MAGIC[:3]),
        ("bad_sync",        b"ABCD" + bytes(4)),
        ("missing_payload", MAGIC + b"\x01\x20\x00" + b"A"),
        ("zero_length",     packet()),
        ("one_byte",        packet(b"A")),
        ("boundary_64",     packet(b"A" * 64)),
        ("bad_checksum",    packet(b"hello", valid_checksum=False)),
        ("format_string",   packet(b"%x.%x.%n", valid_checksum=False)),
        ("overflow_65",     packet(b"A" * 65)),
        ("overflow_128",    packet(b"A" * 128)),
        # ── Seed mới từ DICT_TOKENS ──────────────────────────────────────────
        ("dict_%n",         packet(b"%n%n%n%n", valid_checksum=False)),
        ("dict_null",       packet(b"\x00" * 4)),
        ("dict_ff",         packet(b"\xff" * 8, valid_checksum=False)),
        ("dict_BEGIN",      packet(b"BEGIN")),
        ("dict_DROP",       packet(b"DROP TABLE fuzzer;")),
    ]


# ── Mutation modes ────────────────────────────────────────────────────────────

def assign_mutation_standard(rng, corpus):
    """Mutation gốc: byte/length/checksum/truncate/append/rebuild."""
    name, original = rng.choice(corpus)
    data = bytearray(original)
    op = rng.choice(("byte", "length", "checksum", "truncate", "append", "rebuild"))
    if op == "rebuild":
        size = rng.choice((0, 1, 63, 64, 65, 66, 127, 128))
        data = bytearray(packet(bytes(rng.randrange(256) for _ in range(size)),
                                command=rng.randrange(256),
                                valid_checksum=bool(rng.randrange(2))))
    elif op == "byte" and data:
        pos = rng.randrange(len(data))
        data[pos] = rng.randrange(256)
    elif op == "length" and len(data) >= 7:
        data[5:7] = struct.pack("<H", rng.choice((0, 1, 63, 64, 65, 128, 255, 65535)))
    elif op == "checksum" and data:
        data[-1] ^= rng.randrange(1, 256)
    elif op == "truncate" and data:
        del data[rng.randrange(len(data)):]
    elif op == "append":
        data.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8))))
    return f"{name}:{op}", bytes(data)


def assign_mutation_arith(rng, corpus):
    """Bài 08 – Arithmetic mutation: ±1/huge cho length, bit-flip cho payload."""
    name, original = rng.choice(corpus)
    if len(original) < 8:
        # Dữ liệu quá ngắn → fallback rebuild
        size = rng.choice((0, 63, 64, 65))
        data = packet(bytes(rng.randrange(256) for _ in range(size)),
                      command=rng.randrange(256),
                      valid_checksum=bool(rng.randrange(2)))
        return f"{name}:arith_rebuild", data

    data = bytearray(original)
    # Arithmetic mutation cho trường length (byte 5-6, little-endian)
    length_val = struct.unpack("<H", data[5:7])[0]
    arith_op = rng.choice(("+1", "-1", "huge", "zero"))
    if arith_op == "+1":
        length_val = (length_val + 1) & 0xFFFF
    elif arith_op == "-1":
        length_val = (length_val - 1) & 0xFFFF
    elif arith_op == "huge":
        length_val = rng.choice((0xFFFF, 0xFF00, 0x8000, 0x7FFF))
    else:
        length_val = 0
    data[5:7] = struct.pack("<H", length_val)

    # Bit-flip tự do cho payload (sau byte 7)
    if len(data) > 7:
        idx = rng.randrange(7, len(data))
        data[idx] ^= 1 << rng.randrange(8)

    return f"{name}:arith_{arith_op}", bytes(data)


def assign_mutation_dict(rng, corpus):
    """Bài 09 – Dictionary-guided: chen token đặc biệt vào payload."""
    name, original = rng.choice(corpus)
    token = rng.choice(DICT_TOKENS)
    # Ghép token vào payload → tăng P(format-string / boundary hit)
    use_valid = rng.random() > 0.5
    data = packet(token, command=rng.randrange(256), valid_checksum=use_valid)
    return f"{name}:dict_{token[:4].hex()}", data


def assign_mutation_loop(rng, corpus, prev_data: bytes | None):
    """Nhánh MỚI – Lặp lại liên tục trên CÙNG dữ liệu (tích lũy trạng thái).

    Mỗi lần gán lại một trường ngẫu nhiên ngay trên kết quả trước,
    mô phỏng kịch bản: input bị ghi đè nhiều lần trước khi parser nhận.
    Đây là vector dẫn đến crash/hang khi state machine không thoát.
    """
    if prev_data is None or len(prev_data) == 0:
        name, base = rng.choice(corpus)
        prev_data = base
        name = name
    else:
        # Tìm tên gần nhất trong corpus để làm nhãn
        name = "loop_carry"

    data = bytearray(prev_data)
    # Chọn thao tác gán lại nhỏ → tích lũy nhiều lần
    op = rng.choice(("byte", "checksum", "length", "append", "token_inject"))
    if op == "byte" and data:
        pos = rng.randrange(len(data))
        data[pos] = rng.randrange(256)
    elif op == "checksum" and data:
        data[-1] ^= rng.randrange(1, 256)
    elif op == "length" and len(data) >= 7:
        data[5:7] = struct.pack("<H", rng.choice((0, 1, 64, 65, 255, 65535)))
    elif op == "append":
        data.extend(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4))))
    elif op == "token_inject":
        token = rng.choice(DICT_TOKENS)
        if len(data) > 7:
            inject_pos = rng.randrange(7, len(data))
            data[inject_pos:inject_pos + len(token)] = token
        else:
            data.extend(token)
    return f"{name}:{op}", bytes(data)


def modeled_state(data):
    """7 trạng thái phân tích input (input/observable states)."""
    if not data:
        return "empty_file"
    if len(data) < 8:
        return "too_short"
    if data[:4] != MAGIC:
        return "sync_mismatch"
    length = struct.unpack("<H", data[5:7])[0]
    if len(data) < 8 + length:
        return "length_mismatch"
    if length > 64:
        return "oversized_payload"
    checksum = 0
    for value in data[:7 + length]:
        checksum ^= value
    return "parse_ok" if data[7 + length] == checksum else "checksum_invalid"


def run_case(executable, input_path, timeout):
    started = time.monotonic()
    try:
        result = subprocess.run([str(executable), str(input_path)], cwd=ROOT,
                                capture_output=True, timeout=timeout)
        output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
        code = result.returncode
        kind = "normal" if code in (0, 1) else "crash"
    except subprocess.TimeoutExpired as exc:
        code, kind = None, "hang"
        output = ((exc.stdout or b"") + (exc.stderr or b"")).decode("utf-8", errors="replace")
    except OSError as exc:
        code, kind, output = None, "runner_exception", repr(exc)
    return {
        "kind": kind,
        "exit_code": code,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        "output": output[-12000:],
    }


def gcov_summary(build_dir, coverage_dir, source_file):
    """Chay gcov voi gcno/gcda dung ten.

    GCC --coverage tren Windows dat ten file theo pattern:
        <exe_stem>-<source_stem>.gcno / .gcda
    Vi du: parser_coverage-network_parser_v0.gcno

    gcov yeu cau ten .gcno khop voi source stem khi dung -o <dir>.
    Giai phap: rename sang <source_stem>.gcno/.gcda trong coverage_dir.
    """
    source_stem = source_file.stem          # "network_parser_v0"
    gcno_files  = list(build_dir.glob("*.gcno"))
    gcda_files  = list(build_dir.glob("*.gcda"))

    # Rename / copy sang <source_stem>.gcno / .gcda trong coverage_dir
    for src in gcno_files:
        dst = coverage_dir / f"{source_stem}.gcno"
        shutil.copy2(src, dst)
    for src in gcda_files:
        dst = coverage_dir / f"{source_stem}.gcda"
        shutil.copy2(src, dst)

    proc = subprocess.run(
        ["gcov", "-b", "-c", "-o", str(coverage_dir), str(source_file)],
        cwd=coverage_dir, capture_output=True, text=True,
    )
    output = proc.stdout + proc.stderr
    (coverage_dir / "gcov_output.txt").write_text(output, encoding="utf-8")
    for path in coverage_dir.glob("*.gcov"):
        if path.name != "network_parser_v0.c.gcov":
            path.unlink()
    branch = re.search(r"Branches executed:([0-9.]+)% of (\d+)", output)
    taken  = re.search(r"Taken at least once:([0-9.]+)% of (\d+)", output)
    lines  = re.search(r"Lines executed:([0-9.]+)% of (\d+)", output)
    return {
        "gcov_exit_code": proc.returncode,
        "gcov_raw": output[:500],
        "lines_executed_percent": float(lines.group(1)) if lines else None,
        "branches_executed_percent": float(branch.group(1)) if branch else None,
        "branches_taken_percent": float(taken.group(1)) if taken else None,
        "branch_total": int(branch.group(2)) if branch else None,
    }


def symbolic_cost_summary():
    """Bài 10 – Ước lượng chi phí symbolic execution của parser."""
    independent_cost = N_INDEPENDENT_BRANCHES          # O(n) = 7
    nested_cost      = 2 ** N_NESTED_DEPTH             # O(2^5) = 32
    return {
        "independent_branches": N_INDEPENDENT_BRANCHES,
        "independent_solver_calls_O_n": independent_cost,
        "nested_depth": N_NESTED_DEPTH,
        "nested_solver_calls_O_2n": nested_cost,
        "speedup_ratio_dict_vs_random": round(
            (1 / 20) / ((1 / 256) ** 5), 3),           # bài 09: P_dict / P_random
        "note": ("7 independent branches -> O(7) solver calls; "
                 "5-depth nested -> O(32) calls; "
                 "dictionary token 'BEGIN' hits 1.8e10x more often than random."),
    }


def save_loop_crash(loop_crash_dir: Path, run_name: str,
                    case_id: str, data: bytes, record: dict):
    """Lưu crash/hang từ chế độ loop vào thư mục riêng."""
    loop_crash_dir.mkdir(parents=True, exist_ok=True)
    dest = loop_crash_dir / run_name
    dest.mkdir(exist_ok=True)
    bin_path = dest / f"{case_id}_{record['kind']}.bin"
    bin_path.write_bytes(data)
    meta_path = dest / f"{case_id}_{record['kind']}.json"
    meta_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    # Append vào master log của thư mục loop_crash
    master = loop_crash_dir / "all_crashes.jsonl"
    with master.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"run": run_name, **record}, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds",     type=int,   default=3)
    parser.add_argument("--iterations", type=int,   default=100, help="cases per round")
    parser.add_argument("--seed",       type=int,   default=20261019)
    parser.add_argument("--timeout",    type=float, default=0.5, help="seconds per process")
    parser.add_argument(
        "--mode",
        choices=("standard", "arith", "dict", "loop", "all"),
        default="all",
        help=(
            "Chế độ mutation: "
            "standard=gốc, arith=bài08 arithmetic, "
            "dict=bài09 dictionary, loop=lặp lại liên tục, all=kết hợp (mặc định)"
        ),
    )
    args = parser.parse_args()
    if args.rounds < 1 or args.iterations < 1 or args.timeout <= 0:
        parser.error("rounds, iterations and timeout must be positive")
    if not shutil.which("gcc") or not shutil.which("gcov"):
        parser.error("gcc and gcov are required on PATH")

    run_name = datetime.now().strftime("run_%Y%m%d_%H%M%S_%f")
    run_dir      = LOG_ROOT / run_name
    build_dir    = run_dir / "build"
    findings_dir = run_dir / "findings"
    coverage_dir = run_dir / "coverage"
    for folder in (build_dir, findings_dir, coverage_dir):
        folder.mkdir(parents=True)

    # ── Compile với --coverage (gcov) ─────────────────────────────────────────
    source_c = ROOT / "network_parser_v0.c"
    executable = build_dir / "parser_coverage.exe"
    compile_result = subprocess.run(
        ["gcc", "--coverage", "-O0", "-g",
         "-o", str(executable), str(source_c), "-Wall"],
        cwd=build_dir, capture_output=True, text=True,
    )
    (run_dir / "compile.log").write_text(
        compile_result.stdout + compile_result.stderr, encoding="utf-8")
    if compile_result.returncode:
        raise SystemExit(f"Compile failed; see {run_dir / 'compile.log'}")

    # ── Xác định bộ mutator theo --mode ───────────────────────────────────────
    mode = args.mode
    print(f"[dynafuzz] mode={mode}  rounds={args.rounds}  "
          f"iterations={args.iterations}  seed={args.seed}")

    rng = random.Random(args.seed)
    corpus = seeds()
    counts = Counter()
    states = set()
    findings = []
    loop_carry: bytes | None = None          # mang trạng thái qua vòng lặp loop
    started = time.monotonic()
    input_path = build_dir / "current_input.bin"

    with (run_dir / "cases.jsonl").open("w", encoding="utf-8") as log:
        for round_index in range(args.rounds):
            loop_carry = None                # reset mỗi round
            for index in range(args.iterations):
                # ── Chọn dữ liệu ─────────────────────────────────────────────
                if index < len(corpus):
                    origin, data = corpus[index]
                else:
                    # Chọn mutator theo mode
                    if mode == "standard":
                        origin, data = assign_mutation_standard(rng, corpus)
                    elif mode == "arith":
                        origin, data = assign_mutation_arith(rng, corpus)
                    elif mode == "dict":
                        origin, data = assign_mutation_dict(rng, corpus)
                    elif mode == "loop":
                        origin, data = assign_mutation_loop(rng, corpus, loop_carry)
                        loop_carry = data    # tích lũy sang iteration tiếp
                    else:  # "all" – round-robin kết hợp
                        pick = (round_index * args.iterations + index) % 4
                        if pick == 0:
                            origin, data = assign_mutation_standard(rng, corpus)
                        elif pick == 1:
                            origin, data = assign_mutation_arith(rng, corpus)
                        elif pick == 2:
                            origin, data = assign_mutation_dict(rng, corpus)
                        else:
                            origin, data = assign_mutation_loop(rng, corpus, loop_carry)
                            loop_carry = data

                # ── Ghi file và chạy parser ───────────────────────────────────
                input_path.write_bytes(data)
                state  = modeled_state(data)
                result = run_case(executable, input_path, args.timeout)
                case_id = f"r{round_index + 1:02d}_i{index + 1:04d}"
                states.add(state)
                counts[state]          += 1
                counts[result["kind"]] += 1

                record = {
                    "case_id":   case_id,
                    "origin":    origin,
                    "state":     state,
                    "mode":      mode,
                    "size":      len(data),
                    "sha256":    hashlib.sha256(data).hexdigest(),
                    "input_hex": data.hex(),
                    **result,
                }

                # ── Lưu findings ──────────────────────────────────────────────
                if result["kind"] != "normal":
                    finding_path = findings_dir / f"{case_id}_{result['kind']}.bin"
                    finding_path.write_bytes(data)
                    record["reproducer"] = str(finding_path.relative_to(run_dir))
                    findings.append({k: record[k] for k in
                                     ("case_id", "kind", "state", "exit_code",
                                      "origin", "mode", "reproducer")})
                    # ── Lưu riêng vào dynamic_loop_crash nếu từ loop/arith/dict ─
                    if mode in ("loop", "arith", "dict", "all"):
                        save_loop_crash(LOOP_CRASH_DIR, run_name,
                                        case_id, data, record)

                log.write(json.dumps(record, ensure_ascii=False) + "\n")
                log.flush()

    input_path.unlink(missing_ok=True)

    # ── Coverage ──────────────────────────────────────────────────────────────
    coverage = gcov_summary(build_dir, coverage_dir, source_c)

    # ── Summary ───────────────────────────────────────────────────────────────
    sym_cost = symbolic_cost_summary()
    summary = {
        "seed":                args.seed,
        "rounds":              args.rounds,
        "iterations_per_round": args.iterations,
        "total_cases":         args.rounds * args.iterations,
        "timeout_seconds":     args.timeout,
        "mutation_mode":       mode,
        "elapsed_seconds":     round(time.monotonic() - started, 2),
        "modeled_state_coverage": {
            "covered": sorted(states),
            "missing": sorted(STATES - states),
            "percent": round(100 * len(states) / len(STATES), 2),
        },
        "counts":         dict(counts),
        "source_coverage": coverage,
        "symbolic_cost":  sym_cost,
        "findings":       findings,
    }
    (run_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    out_text = json.dumps({"log_dir": str(run_dir), **summary},
                          ensure_ascii=False, indent=2)
    sys.stdout.write(out_text + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
