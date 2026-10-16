"""Prove `terraguard scan-aws` finds secrets and state left in an S3 bucket (TG-P14).

A clean scan of real buckets proves nothing on its own, because a scanner that reads nothing
also reports nothing. This plants two synthetic objects in the baseline test bucket, scans,
expects the gate to fail, and then removes every version of both objects:

    1. PLANT    a config file holding AWS's published placeholder key, and a fake state file
    2. DETECT   scan-aws must exit 1 and name both objects
    3. REDACT   the report must not contain the key
    4. CLEAN    every version of both objects is deleted, and a rescan exits 0

No real credential is involved. The key is AWS's documentation placeholder, assembled at
runtime so it is never a literal in a tracked file.

    python scripts/demo_aws_secret_scan.py --profile default
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "terraform" / "baseline"
FAKE_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
PLANTED = {
    "terraguard-demo/app.env": f"AWS_ACCESS_KEY_ID={FAKE_KEY}\n",
    "terraguard-demo/terraform.tfstate": '{"version": 4, "resources": []}\n',
}

results: list[tuple[str, bool, str]] = []


def record(step: str, ok: bool, detail: str) -> None:
    results.append((step, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {step}: {detail}")


def scan(args, bucket: str) -> subprocess.CompletedProcess:
    command = [sys.executable, "-m", "terraguard.cli", "scan-aws", "--profile", args.profile]
    command += ["--region", args.region, "--bucket", bucket, "--no-ssm", "--fail-on", "high"]
    return subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True)


def remove_all_versions(s3, bucket: str, key: str) -> None:
    listing = s3.list_object_versions(Bucket=bucket, Prefix=key)
    for item in listing.get("Versions", []) + listing.get("DeleteMarkers", []):
        if item["Key"] == key:
            s3.delete_object(Bucket=bucket, Key=key, VersionId=item["VersionId"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    import boto3

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if ":user/" not in session.client("sts").get_caller_identity()["Arn"]:
        print("refusing to run: use the IAM research user, not root")
        return 2
    out = subprocess.run(
        ["terraform", "output", "-raw", "test_bucket"],
        cwd=str(BASELINE),
        capture_output=True,
        text=True,
    )
    bucket = out.stdout.strip()
    if out.returncode or not bucket.startswith("terraguard-test-"):
        print("cannot read the test bucket from terraform output; is the baseline deployed?")
        return 2
    s3 = session.client("s3")

    try:
        print("\n1. PLANT")
        for key, body in PLANTED.items():
            s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
        record("objects planted", True, f"{len(PLANTED)} synthetic objects in {bucket}")

        print("\n2. DETECT")
        found = scan(args, bucket)
        record("gate fails", found.returncode == 1, f"exit {found.returncode}, expected 1")
        for key in PLANTED:
            record(f"{key.rsplit('/', 1)[-1]} named", key in found.stdout, "in the report")

        print("\n3. REDACT")
        record("key not echoed", FAKE_KEY not in found.stdout + found.stderr, "value absent")
    finally:
        print("\n4. CLEAN")
        for key in PLANTED:
            remove_all_versions(s3, bucket, key)
        left = s3.list_object_versions(Bucket=bucket, Prefix="terraguard-demo/")
        remaining = len(left.get("Versions", [])) + len(left.get("DeleteMarkers", []))
        record("every version removed", remaining == 0, f"{remaining} left")

    after = scan(args, bucket)
    record("rescan is clean", after.returncode == 0, f"exit {after.returncode}, expected 0")

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
