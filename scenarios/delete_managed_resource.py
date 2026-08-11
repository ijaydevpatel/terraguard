#!/usr/bin/env python3
"""DEL-001: delete a managed bucket outside Terraform.

Only ever targets the log bucket, never the state bucket. The guard below is deliberately
paranoid: deleting state would end the project.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402


def main() -> int:
    args = parse_args("DEL-001", __doc__)
    s3 = session(args).client("s3")
    names = [
        b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith("terraguard-logs-")
    ]
    require(len(names) == 1, f"expected one terraguard-logs-* bucket, found {len(names)}")
    bucket = names[0]
    require("state" not in bucket, "refusing to touch anything that looks like the state bucket")

    contents = s3.list_objects_v2(Bucket=bucket).get("KeyCount", 0)
    require(contents == 0, "log bucket is not empty; empty it first so the delete is clean")

    if args.dry_run:
        record(args, "dry-run", {"bucket": bucket})
        return 0

    s3.delete_bucket(Bucket=bucket)
    record(args, "injected", {"bucket": bucket, "change": "bucket deleted out of band"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
