"""Verify pass. No installs, no network, nothing that can hang.

Run this after opening the tracker in Excel once and saving, which is what repopulates the
Dashboard's cached formula values. openpyxl strips them on write, so the consistency checker
reads them as None until Excel has recalculated.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOK = ROOT.parent / "TerraGuard_Build_Tracker.xlsx"
LOG = ROOT / "build/verify_log.txt"
_lines: list[str] = []


def say(text: str = "") -> None:
    print(text)
    _lines.append(text)
    LOG.write_text("\n".join(_lines), encoding="utf-8")


def main() -> int:
    from openpyxl import load_workbook

    wb = load_workbook(BOOK)
    wv = load_workbook(BOOK, data_only=True)

    say("=== Dashboard")
    dash = wv["Dashboard"]
    blank = 0
    for r in range(1, dash.max_row + 1):
        label = dash.cell(r, 1).value
        if not label:
            continue
        value = dash.cell(r, 2).value
        if value is None and isinstance(wb["Dashboard"].cell(r, 2).value, str):
            blank += 1
        say(f"  {str(label):42s} {value}")
    if blank:
        say(f"\n  {blank} formula cells have no cached value.")
        say("  Open the workbook in Excel and save once, then re-run this script.")

    say("\n=== sheet inventory")
    for ws in wb.worksheets:
        rows = sum(1 for r in range(1, ws.max_row + 1) if ws.cell(r, 1).value)
        say(f"  {ws.title:16s} {rows} populated rows")

    tt = wb["Task Tracker"]
    from collections import Counter

    status = Counter(tt.cell(r, 10).value for r in range(5, tt.max_row + 1) if tt.cell(r, 7).value)
    say(f"\n=== task status  {dict(status)}")

    say("\n=== consistency checker")
    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_tracker.py"), str(BOOK)],
        capture_output=True,
        text=True,
    )
    say((check.stdout + check.stderr).strip() or "(no output)")

    say("\n=== lint and tests")
    for label, args in (
        ("ruff", [sys.executable, "-m", "ruff", "check", "terraguard", "scripts", "tests"]),
        (
            "black",
            [
                sys.executable,
                "-m",
                "black",
                "--check",
                "--line-length",
                "100",
                "terraguard",
                "scripts",
                "tests",
                "scenarios",
            ],
        ),
        ("pytest", [sys.executable, "-m", "pytest", "-q"]),
    ):
        proc = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=900)
        tail = "\n".join(((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()[-6:])
        say(f"\n  [{label}] exit {proc.returncode}\n{tail}")

    say("\n=== git")
    for args in (["git", "status", "--short"], ["git", "log", "--oneline", "-3"]):
        proc = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True)
        say((proc.stdout or "").strip()[:1500])

    say("\nDONE")
    return 0


if __name__ == "__main__":
    say("starting verify")
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException:
        import traceback

        say("!! failed")
        say(traceback.format_exc()[-2500:])
        raise SystemExit(1) from None
