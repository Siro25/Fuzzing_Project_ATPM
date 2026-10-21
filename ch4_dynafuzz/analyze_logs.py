"""Phân tích log dynamic fuzzing để tìm các trường hợp ngoại lệ.

Usage
-----
    python ch4_dynafuzz/analyze_logs.py [--run <run_folder>] [--report {text,json,html}]

Không có --run → phân tích TẤT CẢ run trong logs/ và logs/dynamic_loop_crash/.

Phân loại ngoại lệ được phát hiện
-----------------------------------
1.  crash_nonzero     – exit code ≠ 0,1,None
2.  hang              – parser không thoát trong timeout
3.  runner_exception  – lỗi OS khi spawn process
4.  format_string_hit – output chứa địa chỉ hex leak (nghi CWE-134)
5.  overflow_hit      – size > 64 + crash (nghi CWE-120)
6.  oob_read_hit      – state=length_mismatch + declared_len lớn + crash (nghi CWE-125)
7.  loop_carry_crash  – crash từ iteration loop_carry (crash tích lũy)
8.  unexpected_state  – state không nằm trong KNOWN_STATES
"""

import argparse
import json
import re
import sys

# Ensure UTF-8 stdout on Windows to avoid CP1252 UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime

LOG_ROOT      = Path(__file__).resolve().parent / "logs"
LOOP_CRASH_DIR = LOG_ROOT / "dynamic_loop_crash"

KNOWN_STATES = {
    "empty_file", "too_short", "sync_mismatch", "length_mismatch",
    "checksum_invalid", "parse_ok", "oversized_payload",
}

# Regex phát hiện hex-address leak trong output (nghi format string exploit)
HEX_ADDR_RE = re.compile(r"\b[0-9a-fA-F]{6,16}\b")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def iter_cases(jsonl_path: Path):
    """Yield từng record từ cases.jsonl."""
    with jsonl_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass


def classify_case(rec: dict) -> list[str]:
    """Return list of exception tags for one fuzzing case.

    Detection rules:
      1. crash_nonzero     -- exit code != 0,1,None
      2. hang              -- parser timed out
      3. runner_exception  -- OS error spawning process
      4. format_string_hit -- output has format-specifier artifacts (CWE-134)
      5. overflow_hit      -- size > 72 + crash (CWE-120)
      6. oversized_accepted-- parse_ok with payload > 64 bytes (memcpy overflow
                              taken silently, CWE-120 evidence on Windows)
      7. oob_read_hit      -- length_mismatch + crash (CWE-125)
      8. loop_carry_crash  -- crash from accumulated loop_carry data
      9. unexpected_state  -- state outside KNOWN_STATES
    """
    tags = []
    kind      = rec.get("kind", "normal")
    state     = rec.get("state", "")
    origin    = rec.get("origin", "")
    size      = rec.get("size", 0)
    output    = rec.get("output", "")
    input_hex = rec.get("input_hex", "")

    # 1. Crash / hang / runner_exception
    if kind == "hang":
        tags.append("hang")
    elif kind == "runner_exception":
        tags.append("runner_exception")
    elif kind == "crash":
        tags.append("crash_nonzero")

    # 2. Format string evidence in OUTPUT
    # Parser prints payload via printf(temp) [CWE-134]; if payload contained
    # %x/%s/%n the output will show leaked stack values or skip chars.
    fmt_in_output = (
        re.search(r"0x[0-9a-fA-F]{4,}", output) or           # hex pointer in output
        re.search(r"\b[0-9a-fA-F]{8,16}\b", output) or       # raw hex dump
        ("%x" in output) or ("%s" in output) or ("%n" in output)
    )
    fmt_in_input = (
        "%x" in bytes.fromhex(input_hex).decode("latin-1") if input_hex else False
        or "%n" in bytes.fromhex(input_hex).decode("latin-1") if input_hex else False
        or "%s" in bytes.fromhex(input_hex).decode("latin-1") if input_hex else False
    )
    if fmt_in_output and (fmt_in_input or "dict_" in origin or "format_string" in origin):
        tags.append("format_string_hit")

    # 3. Buffer overflow path taken without crash (CWE-120, Windows silent)
    # parse_ok means memcpy(payload, data, data_len) succeeded with data_len > 64
    # Actual overflow: declared length > MAX_PAYLOAD_SIZE (64)
    if state == "oversized_payload" and kind == "normal":
        # Parser rejected it -- correct behavior
        pass
    if state == "parse_ok" and size > 72:
        # parse_ok with total packet > 72 bytes means data_len declared > 64
        # and memcpy wrote past payload[64] buffer boundary -> CWE-120 (silent)
        tags.append("oversized_accepted")

    # 4. Buffer overflow with crash
    if size > 72 and kind in ("crash", "hang"):
        tags.append("overflow_hit")

    # 5. OOB read: length_mismatch + crash
    if state == "length_mismatch" and kind in ("crash", "hang"):
        tags.append("oob_read_hit")

    # 6. Loop carry crash
    if "loop_carry" in origin or ":token_inject" in origin:
        if kind in ("crash", "hang"):
            tags.append("loop_carry_crash")

    # 7. Unexpected state
    if state and state not in KNOWN_STATES:
        tags.append("unexpected_state")

    return tags



def scan_run(run_dir: Path):
    """Quét 1 thư mục run, trả về dict kết quả."""
    cases_file = run_dir / "cases.jsonl"
    summary_file = run_dir / "summary.json"
    if not cases_file.exists():
        return None

    total = 0
    tag_counts: Counter = Counter()
    findings_by_tag: defaultdict[str, list] = defaultdict(list)
    state_counts: Counter = Counter()
    mode_counts:  Counter = Counter()
    covered_states = set()

    for rec in iter_cases(cases_file):
        total += 1
        state = rec.get("state", "unknown")
        mode  = rec.get("mode", "standard")
        state_counts[state] += 1
        mode_counts[mode]   += 1
        covered_states.add(state)

        tags = classify_case(rec)
        if tags:
            for t in tags:
                tag_counts[t] += 1
                # Giữ tối đa 10 ví dụ per tag để không bloat report
                if len(findings_by_tag[t]) < 10:
                    findings_by_tag[t].append({
                        "case_id":   rec.get("case_id"),
                        "origin":    rec.get("origin"),
                        "state":     state,
                        "kind":      rec.get("kind"),
                        "exit_code": rec.get("exit_code"),
                        "size":      rec.get("size"),
                        "sha256":    rec.get("sha256", "")[:16],
                        "mode":      mode,
                        "output_snippet": rec.get("output", "")[:200],
                    })

    summary = {}
    if summary_file.exists():
        try:
            summary = json.loads(summary_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    missing_states = sorted(KNOWN_STATES - covered_states)
    return {
        "run":              run_dir.name,
        "total_cases":      total,
        "mode":             summary.get("mutation_mode", "?"),
        "state_coverage_pct": round(100 * len(covered_states & KNOWN_STATES) / len(KNOWN_STATES), 1),
        "missing_states":   missing_states,
        "tag_counts":       dict(tag_counts),
        "state_counts":     dict(state_counts),
        "mode_counts":      dict(mode_counts),
        "source_coverage":  summary.get("source_coverage", {}),
        "symbolic_cost":    summary.get("symbolic_cost", {}),
        "findings_by_tag":  {k: v for k, v in findings_by_tag.items()},
    }


def scan_loop_crash_master():
    """Quét master log all_crashes.jsonl trong dynamic_loop_crash."""
    master = LOOP_CRASH_DIR / "all_crashes.jsonl"
    if not master.exists():
        return None
    total = 0
    tag_counts: Counter = Counter()
    examples = defaultdict(list)
    for rec in iter_cases(master):
        total += 1
        tags = classify_case(rec)
        for t in tags:
            tag_counts[t] += 1
            if len(examples[t]) < 5:
                examples[t].append(rec.get("case_id", "?"))
    return {
        "source": "dynamic_loop_crash/all_crashes.jsonl",
        "total_loop_crashes": total,
        "exception_counts": dict(tag_counts),
        "examples_per_tag": dict(examples),
    }


# ─── Report renderers ─────────────────────────────────────────────────────────

def render_text(results: list[dict], loop_crash_summary):
    lines = []
    lines.append("=" * 70)
    lines.append("  DYNAMIC FUZZING LOG ANALYSIS REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    for r in results:
        lines.append(f"\n{'─'*60}")
        lines.append(f"  Run : {r['run']}")
        lines.append(f"  Mode: {r['mode']}   Total cases: {r['total_cases']}")
        lines.append(f"  State coverage : {r['state_coverage_pct']}%   "
                     f"Missing: {r['missing_states'] or '(none)'}")
        sc = r.get("source_coverage", {})
        if sc.get("lines_executed_percent") is not None:
            lines.append(f"  gcov lines     : {sc['lines_executed_percent']}%  "
                         f"branches executed: {sc.get('branches_executed_percent')}%  "
                         f"taken: {sc.get('branches_taken_percent')}%")
        sym = r.get("symbolic_cost", {})
        if sym:
            lines.append(f"  Symbolic cost  : O(n)={sym.get('independent_solver_calls_O_n')} calls  "
                         f"O(2^n)={sym.get('nested_solver_calls_O_2n')} calls  "
                         f"dict speedup={sym.get('speedup_ratio_dict_vs_random'):.2e}")
        if r["tag_counts"]:
            lines.append("  Exceptions found:")
            for tag, cnt in sorted(r["tag_counts"].items(), key=lambda x: -x[1]):
                lines.append(f"    [{tag:25s}] x {cnt}")
                for ex in r["findings_by_tag"].get(tag, [])[:3]:
                    lines.append(f"      -> {ex['case_id']} | {ex['origin']} | "
                                 f"state={ex['state']} | kind={ex['kind']} | "
                                 f"size={ex['size']}")
        else:
            lines.append("  No exceptions detected in this run.")

    if loop_crash_summary:
        lines.append("\n" + "=" * 60)
        lines.append("  LOOP CRASH MASTER LOG SUMMARY")
        lines.append(f"  Source: {loop_crash_summary['source']}")
        lines.append(f"  Total recorded loop crashes : {loop_crash_summary['total_loop_crashes']}")
        for tag, cnt in sorted(loop_crash_summary["exception_counts"].items(),
                                key=lambda x: -x[1]):
            examples = loop_crash_summary["examples_per_tag"].get(tag, [])
            lines.append(f"    [{tag:25s}] x {cnt}  e.g. {examples}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def render_json(results, loop_crash_summary):
    return json.dumps({
        "generated": datetime.now().isoformat(),
        "runs": results,
        "loop_crash_summary": loop_crash_summary,
    }, ensure_ascii=False, indent=2)


def render_html(results, loop_crash_summary):
    rows = ""
    for r in results:
        tags_html = "<br>".join(
            f"<b>{tag}</b>: {cnt}" for tag, cnt in r["tag_counts"].items()
        ) or "<em>none</em>"
        sc = r.get("source_coverage", {})
        cov_str = (f"{sc.get('lines_executed_percent')}% lines / "
                   f"{sc.get('branches_taken_percent')}% branches taken"
                   if sc.get("lines_executed_percent") else "gcov N/A")
        rows += f"""
        <tr>
          <td>{r['run']}</td>
          <td>{r['mode']}</td>
          <td>{r['total_cases']}</td>
          <td>{r['state_coverage_pct']}%</td>
          <td>{cov_str}</td>
          <td>{tags_html}</td>
        </tr>"""

    loop_section = ""
    if loop_crash_summary:
        loop_rows = "".join(
            f"<tr><td>{t}</td><td>{c}</td>"
            f"<td>{', '.join(loop_crash_summary['examples_per_tag'].get(t,[]))}</td></tr>"
            for t, c in loop_crash_summary["exception_counts"].items()
        )
        loop_section = f"""
        <h2>🔴 Loop-Crash Master Log</h2>
        <p>Total: <b>{loop_crash_summary['total_loop_crashes']}</b> crash/hang events</p>
        <table><thead><tr><th>Exception tag</th><th>Count</th><th>Examples</th></tr></thead>
        <tbody>{loop_rows}</tbody></table>
        """

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>DynaFuzz Log Analysis</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; margin: 2rem; }}
  h1 {{ color: #7ee8a2; }}
  h2 {{ color: #61dafb; margin-top: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th {{ background: #1e2230; color: #7ee8a2; padding: .6rem 1rem; text-align: left; }}
  td {{ border-top: 1px solid #2a2d3e; padding: .5rem 1rem; vertical-align: top; }}
  tr:hover td {{ background: #1a1d2e; }}
  .none {{ color: #888; font-style: italic; }}
  .tag {{ color: #ff7eb3; font-weight: bold; }}
  footer {{ margin-top: 3rem; color: #555; font-size: .8rem; }}
</style>
</head>
<body>
<h1>🧪 Dynamic Fuzzing – Log Analysis Report</h1>
<p>Generated: {now}</p>
<h2>📊 Per-Run Summary</h2>
<table>
<thead>
  <tr><th>Run</th><th>Mode</th><th>Cases</th><th>State cov</th><th>gcov</th><th>Exceptions</th></tr>
</thead>
<tbody>{rows}</tbody>
</table>
{loop_section}
<footer>ch4_dynafuzz/analyze_logs.py · ATPM Fuzzing Project</footer>
</body>
</html>"""


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run",    help="Chỉ phân tích 1 run folder cụ thể (tên, không cần path đầy đủ)")
    ap.add_argument("--report", choices=("text", "json", "html"), default="text")
    ap.add_argument("--out",    help="Ghi output ra file (mặc định: stdout)")
    args = ap.parse_args()

    # Thu thập danh sách run directories
    if args.run:
        candidates = [LOG_ROOT / args.run]
    else:
        candidates = sorted(LOG_ROOT.iterdir(), reverse=True)

    results = []
    for d in candidates:
        if not d.is_dir():
            continue
        if d.name in ("dynamic_loop_crash", "chapter_baseline", "json_fuzz_corpus"):
            continue
        r = scan_run(d)
        if r:
            results.append(r)

    loop_crash_summary = scan_loop_crash_master()

    if not results and not loop_crash_summary:
        print("[analyze_logs] Không tìm thấy log nào. Chạy run_dynamic_fuzz.py trước.",
              file=sys.stderr)
        sys.exit(1)

    if args.report == "text":
        output = render_text(results, loop_crash_summary)
    elif args.report == "json":
        output = render_json(results, loop_crash_summary)
    else:
        output = render_html(results, loop_crash_summary)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        sys.stdout.write(f"[analyze_logs] Report saved -> {args.out}\n")
        sys.stdout.flush()
    else:
        sys.stdout.write(output + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
