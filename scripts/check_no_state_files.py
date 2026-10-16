#!/usr/bin/env python3
"""Pre-commit guard: refuse to commit Terraform state, plan files, or secrets.

TG-P01 and TG-P06 are the controls this hook enforces at source. It is deliberately blunt:
a false positive costs one --no-verify argument, a false negative costs a leak.

Until 16 Oct it blocked state files, plans and AWS access key ids only. A password has no
recognisable shape, so `db_password = "..."` went straight through; the scanner flagged it
afterwards, but by then the commit existed. The hook now runs the scanner's own content rule,
including the key-name check and `.terraguardignore`, so the two can never disagree.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BLOCKED_PATTERNS = [
    re.compile(r"\.tfstate$"),
    re.compile(r"\.tfstate\.backup$"),
    re.compile(r"\.tfstate\.\d+\.backup$"),
    re.compile(r"(^|/)tfplan(\.\w+)?$"),
    re.compile(r"\.tfplan$"),
    re.compile(r"(^|/)(tfplan|plan)\.json$"),
]

# Paths that are allowed to look like plan JSON because they are sanitised fixtures.
ALLOWLIST_PREFIXES = ("tests/fixtures/", "datasets/", "terraform/fixtures/")

# Any file containing a real-looking AWS key is blocked regardless of name.
AWS_KEY = re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")


def is_allowlisted(path: str) -> bool:
    return any(path.startswith(p) for p in ALLOWLIST_PREFIXES)


def secret_findings(paths: list[str]) -> list[str]:
    """Run the scanner's TG-P06 content rule. Reports key names and lengths, never values."""
    try:
        from terraguard.repository_scanner import scan_file_contents
    except ImportError:
        return []  # outside this repository the AWS key check above still applies
    return [f"{f.resource_address}: {f.detail}" for f in scan_file_contents(Path.cwd(), paths)]


def main(argv: list[str]) -> int:
    failures: list[str] = []
    to_scan: list[str] = []
    for name in argv:
        posix = Path(name).as_posix()
        if is_allowlisted(posix):
            continue
        for pattern in BLOCKED_PATTERNS:
            if pattern.search(posix):
                failures.append(f"{posix}: matches blocked pattern {pattern.pattern!r}")
                break
        else:
            try:
                text = Path(posix).read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            if AWS_KEY.search(text):
                failures.append(f"{posix}: contains what looks like an AWS access key id")
            else:
                to_scan.append(posix)
    failures += secret_findings(to_scan)

    if failures:
        sys.stderr.write("\nBLOCKED by check_no_state_files.py (TG-P01, TG-P06):\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.stderr.write(
            "\nState and plan files hold secrets in cleartext, and so does any file with a\n"
            "password, token or key in it. Do not commit them. Use a remote encrypted backend\n"
            "for state and a secret store or environment variable for credentials.\n\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
