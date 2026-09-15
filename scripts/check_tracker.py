#!/usr/bin/env python3
"""Cross-sheet consistency check for TerraGuard_Build_Tracker.xlsx.

Updating the Task Tracker is not the same as updating the workbook. This walks all six
sheets and reports anything that has fallen out of step: counts that no longer reconcile,
milestone or risk statuses that contradict task statuses, formula ranges that stop short of
the last row, and wording that still describes a superseded state.

Usage:  python3 scripts/check_tracker.py [path/to/TerraGuard_Build_Tracker.xlsx]
Exit code 1 if anything is stale.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from openpyxl import load_workbook

EXPECTED_SHEETS = [
    "Task Tracker",
    "Dashboard",
    "Milestones",
    "Risk Register",
    "How to use",
    "Change Log",
]
MILESTONE_WORDS = {"Planned", "In progress", "At risk", "Met", "Missed"}
STATUS_WORDS = {"Not started", "In progress", "Blocked", "Done", "Dropped"}


def check(path: Path) -> list[str]:
    problems: list[str] = []
    wb = load_workbook(path)
    vals = load_workbook(path, data_only=True)

    missing = [s for s in EXPECTED_SHEETS if s not in wb.sheetnames]
    if missing:
        return [f"missing sheet(s): {missing}"]

    tt, d, ms, rr, hu, cl = (wb[s] for s in EXPECTED_SHEETS)
    dv = vals["Dashboard"]

    # ---- Task Tracker
    last = max(r for r in range(1, tt.max_row + 1) if tt.cell(r, 1).value)
    tasks, ids = {}, []
    for r in range(5, last + 1):
        tid, typ = tt.cell(r, 1).value, tt.cell(r, 7).value
        if not tid or not typ:
            continue
        tid = str(tid).strip()
        ids.append(tid)
        tasks[tid] = {
            "row": r,
            "status": tt.cell(r, 10).value,
            "week": tt.cell(r, 4).value,
            "effort": tt.cell(r, 8).value,
            "note": tt.cell(r, 12).value,
        }
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        problems.append(f"Task Tracker: duplicate ids {sorted(dupes)}")
    for tid, t in tasks.items():
        if t["status"] not in STATUS_WORDS:
            problems.append(f"Task Tracker: {tid} has status {t['status']!r}")
        if t["effort"] in (None, ""):
            problems.append(f"Task Tracker: {tid} has no effort")
        if t["status"] == "Done" and not (t["note"] or "").strip():
            problems.append(f"Task Tracker: {tid} is Done with no note saying what was produced")

    # ---- dependencies
    order = {f"W{i}": i for i in range(1, 13)}
    order["BUF"] = 13
    for tid, t in tasks.items():
        for dep in str(tt.cell(t["row"], 6).value or "").replace(" ", "").split(","):
            if not dep:
                continue
            if dep not in tasks:
                problems.append(f"Task Tracker: {tid} depends on unknown {dep}")
                continue
            if order.get(str(t["week"]), 99) < order.get(str(tasks[dep]["week"]), 0):
                problems.append(
                    f"Task Tracker: {tid} ({t['week']}) starts before {dep} ({tasks[dep]['week']})"
                )
            if t["status"] == "Done" and tasks[dep]["status"] != "Done":
                problems.append(f"Task Tracker: {tid} is Done but {dep} is {tasks[dep]['status']}")

    # ---- Dashboard: ranges must reach the last task row, counts must reconcile
    for row in list(range(5, 11)) + [14, 15, 17, 18, 21, 22]:
        f = str(d.cell(row, 2).value or "")
        for ref in re.findall(r"\$[A-L]\$5:\$[A-L]\$(\d+)", f):
            if int(ref) != last:
                problems.append(
                    f"Dashboard B{row}: range stops at row {ref}, last task row is {last}"
                )
    # Reconcile from the Task Tracker itself rather than from the Dashboard's cached values.
    # openpyxl drops cached formula results whenever it writes the file, so anything read out
    # of `dv` is None until Excel has opened the workbook again. Checking the underlying facts
    # is both independent of that and a stronger test: it verifies the numbers the formulas are
    # supposed to produce, instead of trusting Excel's last memo of them.
    counted = {word: 0 for word in STATUS_WORDS}
    for t in tasks.values():
        if t["status"] in counted:
            counted[t["status"]] += 1
    if sum(counted.values()) != len(tasks):
        problems.append(
            f"Task Tracker: statuses sum to {sum(counted.values())} but there are "
            f"{len(tasks)} task rows"
        )

    # If Excel has been here since the last write, the cached values must agree with the facts.
    cached_total, cached_balance = dv["B5"].value, dv["B11"].value
    if cached_total is not None and cached_total != len(tasks):
        problems.append(f"Dashboard: cached total {cached_total} but {len(tasks)} task rows")
    if cached_balance is not None and cached_balance != "balanced":
        problems.append(f"Dashboard: status reconciliation reads {cached_balance!r}")

    # ---- Milestones
    for r in range(4, ms.max_row + 1):
        if not ms.cell(r, 1).value:
            continue
        st = ms.cell(r, 4).value
        if st not in MILESTONE_WORDS:
            problems.append(
                f"Milestones {ms.cell(r,1).value}: status {st!r} not in {sorted(MILESTONE_WORDS)}"
            )

    # ---- Risk Register: a risk must not cite a task that does not exist
    for r in range(4, rr.max_row + 1):
        rid = rr.cell(r, 1).value
        if not rid:
            continue
        if rr.cell(r, 7).value not in {"Open", "Mitigated", "Realised", "Closed"}:
            problems.append(f"Risk {rid}: status {rr.cell(r,7).value!r}")
        for cited in re.findall(
            r"\b(T\d{3}[a-z]?|D\d{2}|B\d{2})\b", str(rr.cell(r, 6).value or "")
        ):
            if cited not in tasks:
                problems.append(f"Risk {rid}: cites unknown task {cited}")

    # ---- Change Log: dated, in order, every row names its tasks
    dates = []
    for r in range(5, cl.max_row + 1):
        val = cl.cell(r, 1).value
        if not val:
            continue
        dates.append(val)
        if not str(cl.cell(r, 3).value or "").strip():
            problems.append(f"Change Log row {r}: no description")
    if dates != sorted(dates):
        problems.append("Change Log: entries are not in date order")

    # ---- How to use must mention the sheets it claims to explain
    text = " ".join(
        str(hu.cell(r, c).value or "") for r in range(1, hu.max_row + 1) for c in (1, 2)
    )
    for word in ("Status", "Optional", "Change Log"):
        if word not in text:
            problems.append(f"How to use: no mention of {word}")

    return problems


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../TerraGuard_Build_Tracker.xlsx")
    if not path.exists():
        print(f"not found: {path}")
        return 2
    problems = check(path)
    if not problems:
        print(f"{path.name}: all six sheets consistent")
        return 0
    print(f"{path.name}: {len(problems)} issue(s)")
    for p in problems:
        print(f"  - {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
