#!/usr/bin/env python3
"""Return the environment to the secure baseline after a scenario.

Runs terraform apply, then confirms with a refresh-only plan that nothing is left over.
A scenario is not finished until this reports zero drift - otherwise the next observation
starts from a contaminated baseline.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record  # noqa: E402

BASELINE = Path("terraform/baseline")


def _run(args: list[str]) -> int:
    return subprocess.run(args, cwd=str(BASELINE), check=False).returncode


def main() -> int:
    args = parse_args("RESTORE", __doc__)
    if args.dry_run:
        record(args, "dry-run", {"action": "would apply baseline and re-check drift"})
        return 0

    if _run(["terraform", "apply", "-input=false", "-auto-approve"]) != 0:
        record(args, "restore-failed", {"stage": "apply"})
        return 1

    code = _run(["terraform", "plan", "-refresh-only", "-input=false", "-detailed-exitcode"])
    if code == 0:
        record(args, "restored", {"drift": "none"})
        return 0
    record(args, "restore-incomplete", {"detailed_exitcode": code})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
