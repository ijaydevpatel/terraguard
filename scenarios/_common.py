"""Shared guards for every injection script.

Three rules every scenario obeys:

1. verify the baseline before touching anything - injecting on top of an unknown state
   produces a record whose ground truth is a guess;
2. change exactly one thing;
3. write a run marker so the observation can be traced back to the manifest.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

RUN_LOG = Path("datasets/injection_runs.jsonl")
BASELINE = Path(__file__).resolve().parents[1] / "terraform" / "baseline"


def parse_args(scenario_id: str, description: str) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--scenario-id", default=scenario_id)
    p.add_argument("--run-id", required=True, help="unique id for this observation")
    p.add_argument("--profile", default="terraguard")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--dry-run", action="store_true", help="verify only, change nothing")
    p.add_argument(
        "--unmanaged",
        action="store_true",
        help="where a scenario supports it, inject a change Terraform does not manage (R25)",
    )
    return p.parse_args()


def session(args):
    import boto3

    return boto3.Session(profile_name=args.profile, region_name=args.region)


def baseline_output(name: str) -> str:
    """Read one output from the baseline stack.

    This replaces `s3.list_buckets()`, which every S3 scenario used to locate its target and
    which needs `s3:ListAllMyBuckets` - an account-wide read that is not in the project's IAM
    policy and should not be. The policy grants `s3:ListBucket`, which sounds like the same
    thing and is not: it lists objects *inside* a named bucket. That one-word difference broke
    four of the seven scenarios with an unhandled botocore error.

    Reading the name from Terraform is better than widening the policy. It needs no AWS
    permission at all, and it cannot pick up an unrelated bucket that happens to share the
    prefix, which the old `startswith` filter would have done silently.
    """
    proc = subprocess.run(
        ["terraform", "output", "-raw", name],
        cwd=str(BASELINE),
        capture_output=True,
        text=True,
        timeout=120,
    )
    require(
        proc.returncode == 0 and proc.stdout.strip() != "",
        f"could not read `terraform output {name}` from {BASELINE}. "
        f"Has the baseline been applied? terraform said: {proc.stderr.strip()[-300:]}",
    )
    return proc.stdout.strip()


def require(condition: bool, message: str) -> None:
    """Abort loudly rather than injecting on top of an unexpected baseline."""
    if not condition:
        sys.stderr.write(f"baseline check failed: {message}\n")
        raise SystemExit(2)


# ARNs carry the 12-digit account id. The run log is committed, so the id is masked on write.
_ACCOUNT_IN_ARN = re.compile(r"(arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:)\d{12}(:)")


def mask_account(text: str) -> str:
    return _ACCOUNT_IN_ARN.sub(r"\1<account>\2", text)


def record(args, action: str, detail: dict) -> None:
    RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "scenario_id": args.scenario_id,
        "run_id": args.run_id,
        "action": action,
        "timestamp": datetime.now(UTC).isoformat(),
        "region": args.region,
        "dry_run": bool(args.dry_run),
        "detail": detail,
    }
    with RUN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    print(json.dumps(entry))
