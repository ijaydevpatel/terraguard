"""Record the three severity-gate outcomes: clean pass, medium warn, critical fail.

Runs the same command the CI gate runs against three fixtures and writes the output, exit
code and wall time of each to results/gate_runs.md. The CI half of T099 is the same three
targets started from the Actions tab with the `target` input; this file is the local record
those runs are compared against (T102).

    python scripts/record_gate_runs.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "gate_runs.md"

RUNS = [
    ("clean pass", "terraform/fixtures/clean", 0),
    ("medium warn", "terraform/fixtures/bk_002_deprecated_lock", 0),
    ("critical fail", "terraform/fixtures/exposed_state", 1),
]


def main() -> int:
    lines = [
        "# Severity gate runs",
        "",
        f"Recorded {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} with",
        "`terraguard scan <target> --no-history --include-optional --fail-on high`.",
        "",
        "| Run | Target | Exit | Expected | Wall time (ms) |",
        "|---|---|---:|---:|---:|",
    ]
    details: list[str] = []
    ok = True
    for name, target, expected in RUNS:
        command = [sys.executable, "-m", "terraguard.cli", "scan", target, "--no-history"]
        command += ["--include-optional", "--fail-on", "high"]
        started = time.perf_counter()
        proc = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True)
        elapsed = (time.perf_counter() - started) * 1000
        ok &= proc.returncode == expected
        lines.append(f"| {name} | `{target}` | {proc.returncode} | {expected} | {elapsed:.0f} |")
        output = (proc.stdout + proc.stderr).strip()
        details += [f"## {name}", "", "```", output, "```", ""]
    lines += ["", *details]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:10]))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
