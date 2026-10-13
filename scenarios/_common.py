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
import sys
from datetime import UTC, datetime
from pathlib import Path

RUN_LOG = Path("datasets/injection_runs.jsonl")


def parse_args(scenario_id: str, description: str) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--scenario-id", default=scenario_id)
    p.add_argument("--run-id", required=True, help="unique id for this observation")
    p.add_argument("--profile", default="terraguard")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--dry-run", action="store_true", help="verify only, change nothing")
    return p.parse_args()


def session(args):
    import boto3

    return boto3.Session(profile_name=args.profile, region_name=args.region)


def require(condition: bool, message: str) -> None:
    """Abort loudly rather than injecting on top of an unexpected baseline."""
    if not condition:
        sys.stderr.write(f"baseline check failed: {message}\n")
        raise SystemExit(2)


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
