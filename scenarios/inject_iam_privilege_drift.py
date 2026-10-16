#!/usr/bin/env python3
"""IAM-001: widen the baseline policy action to a wildcard, outside Terraform.

Creates a new default policy version rather than editing in place, which is how a real
out-of-band privilege change usually happens.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402


def main() -> int:
    args = parse_args("IAM-001", __doc__)
    iam = session(args).client("iam")
    sts = session(args).client("sts")
    account = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:iam::{account}:policy/terraguard-baseline-policy"

    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    version = iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])
    document = version["PolicyVersion"]["Document"]
    statements = document["Statement"]
    require(
        all("*" not in json.dumps(s.get("Action")) for s in statements),
        "policy already contains a wildcard action; baseline is not clean",
    )

    if args.dry_run:
        record(args, "dry-run", {"policy_arn": arn})
        return 0

    # A managed policy holds at most five versions, and every injection and every restore adds
    # one. The third live run on 16 Oct failed with LimitExceeded. Only old, non-default
    # versions are removed, so the version currently in force is never touched.
    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    stale = sorted((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])
    for old in stale[: max(0, len(versions) - 4)]:
        iam.delete_policy_version(PolicyArn=arn, VersionId=old["VersionId"])

    statements[0]["Action"] = "*"
    iam.create_policy_version(PolicyArn=arn, PolicyDocument=json.dumps(document), SetAsDefault=True)
    record(args, "injected", {"policy_arn": arn, "change": "Action widened to *"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
