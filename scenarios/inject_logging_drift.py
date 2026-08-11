#!/usr/bin/env python3
"""LOG-001: stop the CloudTrail trail, outside Terraform."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402

TRAIL = "terraguard-trail"


def main() -> int:
    args = parse_args("LOG-001", __doc__)
    ct = session(args).client("cloudtrail")
    status = ct.get_trail_status(Name=TRAIL)
    require(status.get("IsLogging") is True, "trail is already stopped; baseline is not clean")

    if args.dry_run:
        record(args, "dry-run", {"trail": TRAIL})
        return 0

    ct.stop_logging(Name=TRAIL)
    record(args, "injected", {"trail": TRAIL, "change": "logging stopped"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
