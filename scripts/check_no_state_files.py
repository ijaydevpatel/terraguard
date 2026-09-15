#!/usr/bin/env python3
"""Pre-commit guard: refuse to commit Terraform state, plan or state-derived files.

TG-P01 is the control this hook enforces at source. It is deliberately blunt:
a false positive costs one --no-verify argument, a false negative costs a leak.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

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


def main(argv: list[str]) -> int:
    failures: list[str] = []
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

    if failures:
        sys.stderr.write("\nBLOCKED by check_no_state_files.py (TG-P01):\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.stderr.write(
            "\nTerraform state and plan files may contain secrets in cleartext.\n"
            "Do not commit them. Use a remote encrypted backend instead.\n\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
