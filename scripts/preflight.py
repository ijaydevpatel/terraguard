"""Run locally exactly what CI runs, in CI's order, then commit if everything passes.

The point of this file is that local and CI must not drift. Twice now a run has gone red on
something the local checks never executed: once because black was run over `tests` but not
`scripts`, and once because the state-file guard was not run locally at all, so a test
containing a credential-shaped string reached the repository.

So the steps below are transcribed from `.github/workflows/ci.yml` rather than approximated,
in the same order, with the same paths. CI stops at the first failing step; so does this.

    python scripts/preflight.py           # check only
    python scripts/preflight.py --commit  # check, then commit if green
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOK = ROOT.parent / "TerraGuard_Build_Tracker.xlsx"
LOG = ROOT / "build/preflight_log.txt"
_lines: list[str] = []

COMMIT_MESSAGE = """Fix what the first live dry run exposed and withdraw a result it disproved

Four scenarios located their bucket with s3.list_buckets, which needs s3:ListAllMyBuckets while
the policy grants the similarly named s3:ListBucket; they now read the name from terraform
output and need no account-wide read. A fifth showed that refresh-only cannot see a rule added
out of band, so SG-001 modifies the managed rule instead. No live observation exists in
observations.csv, so M3 and T035 are reverted and the detection claims are synthetic for now."""


def say(text: str = "") -> None:
    print(text)
    _lines.append(text)
    LOG.parent.mkdir(exist_ok=True)
    LOG.write_text("\n".join(_lines), encoding="utf-8")


def run(label: str, args: list[str], timeout: int = 900) -> int:
    proc = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    say(f"\n=== {label}  exit {proc.returncode}")
    say("\n".join(out.splitlines()[-20:]) or "(no output)")
    return proc.returncode


def guard() -> int:
    """CI runs: git ls-files | xargs python scripts/check_no_state_files.py

    xargs splits into several invocations when the list is long; Windows has a shorter
    command-line limit than Linux, so the chunking here is smaller than xargs would use.
    """
    listing = subprocess.run(
        ["git", "ls-files"], cwd=str(ROOT), capture_output=True, text=True
    ).stdout.split()
    say(f"\n=== State and plan file guard  ({len(listing)} tracked files)")
    worst = 0
    for start in range(0, len(listing), 200):
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/check_no_state_files.py"),
                *listing[start : start + 200],
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        if proc.returncode:
            say(((proc.stdout or "") + (proc.stderr or "")).strip())
            worst = proc.returncode
    say("BLOCKED" if worst else "clean")
    return worst


def main() -> int:
    say(f"python {sys.version.split()[0]}")
    say("steps transcribed from .github/workflows/ci.yml, in CI's order")

    # Formatting is applied first so the check below reports only genuine drift.
    run("black (apply)", [sys.executable, "-m", "black", "terraguard", "scripts", "tests", "-q"])

    steps: list[tuple[str, int]] = []
    steps.append(("State and plan file guard", guard()))
    if steps[-1][1] == 0:
        rc = run(
            "Tests",
            [sys.executable, "-m", "pytest", "-q", "--cov=terraguard", "--cov-report=term-missing"],
        )
        if rc != 0:
            rc = run("Tests (no coverage plugin)", [sys.executable, "-m", "pytest", "-q"])
        steps.append(("Tests", rc))
    if all(rc == 0 for _, rc in steps):
        steps.append(
            (
                "Ruff",
                run(
                    "Ruff",
                    [sys.executable, "-m", "ruff", "check", "terraguard", "scripts", "tests"],
                ),
            )
        )
    if all(rc == 0 for _, rc in steps):
        steps.append(
            (
                "Black",
                run(
                    "Black",
                    [
                        sys.executable,
                        "-m",
                        "black",
                        "--check",
                        "--diff",
                        "terraguard",
                        "scripts",
                        "tests",
                    ],
                ),
            )
        )
    if all(rc == 0 for _, rc in steps):
        steps.append(
            (
                "Tracker",
                run(
                    "check_tracker",
                    [sys.executable, str(ROOT / "scripts/check_tracker.py"), str(BOOK)],
                ),
            )
        )

    say("\n=== summary")
    for label, rc in steps:
        say(f"  {label:28s} {'pass' if rc == 0 else 'FAIL'}")
    say("  Gitleaks                     runs in CI only (the action is not installable here)")

    failed = [label for label, rc in steps if rc != 0]
    if failed:
        say(f"\nnot committing - {failed} failed")
        return 1

    if "--commit" in sys.argv:
        run("git add", ["git", "add", "-A"])
        proc = subprocess.run(
            ["git", "commit", "-m", COMMIT_MESSAGE],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        say(f"\n=== git commit  exit {proc.returncode}")
        say(((proc.stdout or "") + (proc.stderr or "")).strip()[-800:])
        run("git log", ["git", "log", "--oneline", "-3"])
        say("\nCommitted. Open GitHub Desktop and press Push origin.")
    else:
        say("\nAll green. Re-run with --commit to commit.")
    say("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
