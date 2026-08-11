#!/usr/bin/env python3
"""S3-002: disable the public access block on the test bucket, outside Terraform.

The bucket policy is left alone, so nothing actually becomes readable. The point is the
control regression, not real exposure - this is a research environment.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402


def main() -> int:
    args = parse_args("S3-002", __doc__)
    s3 = session(args).client("s3")
    names = [
        b["Name"] for b in s3.list_buckets()["Buckets"] if b["Name"].startswith("terraguard-test-")
    ]
    require(len(names) == 1, f"expected one terraguard-test-* bucket, found {len(names)}")
    bucket = names[0]

    current = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    require(all(current.values()), "public access block is already partly disabled")

    if args.dry_run:
        record(args, "dry-run", {"bucket": bucket})
        return 0

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    record(args, "injected", {"bucket": bucket, "change": "BlockPublicAcls disabled"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
