#!/usr/bin/env python3
"""TAG-001: change a tag value. The negative control for severity.

This must be detected as drift but ranked non-security. A model that cannot tell this
apart from an open security group is not doing anything useful.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402


def main() -> int:
    args = parse_args("TAG-001", __doc__)
    s3 = session(args).client("s3")
    names = [
        b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith("terraguard-test-")
    ]
    require(len(names) == 1, f"expected one terraguard-test-* bucket, found {len(names)}")
    bucket = names[0]

    tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    require("Name" in tags, "expected the baseline Name tag to be present")

    if args.dry_run:
        record(args, "dry-run", {"bucket": bucket, "tags": tags})
        return 0

    tags["Owner"] = "research-team-changed"
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}
    )
    record(args, "injected", {"bucket": bucket, "change": "Owner tag changed"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
