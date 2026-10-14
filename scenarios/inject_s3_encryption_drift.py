#!/usr/bin/env python3
"""S3-001: remove default encryption from the test bucket, outside Terraform."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import baseline_output, parse_args, record, require, session  # noqa: E402


def main() -> int:
    args = parse_args("S3-001", __doc__)
    s3 = session(args).client("s3")
    bucket = baseline_output("test_bucket")

    try:
        s3.get_bucket_encryption(Bucket=bucket)
    except Exception:
        require(False, "bucket already has no default encryption; baseline is not clean")

    if args.dry_run:
        record(args, "dry-run", {"bucket": bucket})
        return 0

    s3.delete_bucket_encryption(Bucket=bucket)
    record(args, "injected", {"bucket": bucket, "change": "default encryption removed"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
