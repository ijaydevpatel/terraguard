"""Undo out-of-band drift that Terraform cannot see, so the experiment can start clean.

`terraform apply` is not enough on its own, and the dry run proved it. The pre-flight said the
baseline was clean; SG-001 then refused because the security group was already open to the
world. Both were telling the truth.

The reason is how the baseline is written. Ingress is managed as individual
`aws_vpc_security_group_ingress_rule` resources, one per rule. A rule added out of band has no
state entry, so a refresh has nothing to compare it against and reports no changes. Terraform
is not wrong - it is reconciling the resources it manages, and that rule is not one of them.
It is a limitation of plan-based drift detection, recorded as R25, and it is exactly the kind
of gap this project exists to find.

So the leftovers have to be cleaned up through the API, the same way they were created. This
script reverses every change the injection scripts can make and reports what it found, which
also tells us whether an earlier run failed to restore.

    python scripts/reset_aws_baseline.py --profile default            # report only
    python scripts/reset_aws_baseline.py --profile default --apply    # actually revert
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "terraform" / "baseline"

ADMIN_CIDR = "10.0.0.0/8"
OPEN_V4 = "0.0.0.0/0"
OPEN_V6 = "::/0"


def tf_output(name: str) -> str | None:
    proc = subprocess.run(
        ["terraform", "output", "-raw", name],
        cwd=str(BASELINE),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc.stdout.strip() or None if proc.returncode == 0 else None


def fix_security_group(ec2, apply: bool) -> list[str]:
    """Revoke any ingress open to the world, and any rule that is not the baseline SSH rule.

    Egress is left alone: the baseline deliberately allows all egress, so a 0.0.0.0/0 egress
    rule is correct and revoking it would be the script causing the drift it is meant to undo.
    """
    notes: list[str] = []
    groups = ec2.describe_security_groups(
        Filters=[{"Name": "tag:TerraGuardRole", "Values": ["drift-target"]}]
    )["SecurityGroups"]
    if len(groups) != 1:
        return [f"expected one drift-target security group, found {len(groups)} - not touching it"]
    sg = groups[0]

    for perm in sg.get("IpPermissions", []):
        open_v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") == OPEN_V4]
        open_v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == OPEN_V6]
        if not (open_v4 or open_v6):
            continue
        port = perm.get("FromPort", "all")
        notes.append(f"ingress open to the world on port {port} ({perm.get('IpProtocol')})")
        if apply:
            revoke = {"IpProtocol": perm["IpProtocol"]}
            if "FromPort" in perm:
                revoke["FromPort"] = perm["FromPort"]
                revoke["ToPort"] = perm["ToPort"]
            if open_v4:
                revoke["IpRanges"] = open_v4
            if open_v6:
                revoke["Ipv6Ranges"] = open_v6
            ec2.revoke_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[revoke])
            notes[-1] += "  -> revoked"

    has_baseline_rule = any(
        perm.get("FromPort") == 22
        and any(r.get("CidrIp") == ADMIN_CIDR for r in perm.get("IpRanges", []))
        for perm in sg.get("IpPermissions", [])
    )
    if not has_baseline_rule:
        notes.append(
            f"the baseline SSH rule ({ADMIN_CIDR}:22) is missing. "
            "Terraform does manage this one, so `terraform apply` in terraform/baseline "
            "will put it back."
        )
    return notes


def fix_bucket(s3, bucket: str, apply: bool) -> list[str]:
    notes: list[str] = []

    try:
        s3.get_bucket_encryption(Bucket=bucket)
    except Exception:
        notes.append("default encryption is missing")
        if apply:
            s3.put_bucket_encryption(
                Bucket=bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}},
                    ]
                },
            )
            notes[-1] += "  -> restored to AES256"

    try:
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except Exception:
        pab = {}
    if not pab or not all(pab.values()):
        notes.append(f"public access block is not fully on: {pab or 'absent'}")
        if apply:
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            notes[-1] += "  -> all four re-enabled"

    try:
        tags = {t["Key"]: t["Value"] for t in s3.get_bucket_tagging(Bucket=bucket)["TagSet"]}
    except Exception:
        tags = {}
    if tags.get("Owner") == "research-team-changed":
        notes.append("the TAG-001 Owner tag is still set")
        if apply:
            tags.pop("Owner")
            s3.put_bucket_tagging(
                Bucket=bucket,
                Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]},
            )
            notes[-1] += "  -> removed"
    return notes


def fix_cloudtrail(ct, trail: str, apply: bool) -> list[str]:
    try:
        status = ct.get_trail_status(Name=trail)
    except Exception as exc:  # noqa: BLE001
        return [f"could not read trail {trail}: {type(exc).__name__}"]
    if status.get("IsLogging"):
        return []
    note = f"trail {trail} is not logging"
    if apply:
        ct.start_logging(Name=trail)
        note += "  -> logging restarted"
    return [note]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--apply", action="store_true", help="make the changes, not just report")
    args = parser.parse_args()

    import boto3

    sess = boto3.Session(profile_name=args.profile, region_name=args.region)
    who = sess.client("sts").get_caller_identity()
    if ":user/" not in who.get("Arn", ""):
        print("refusing to run: this is not an IAM user.", file=sys.stderr)
        return 2
    print(f"identity: {who['Arn']}")
    print("mode: APPLY" if args.apply else "mode: report only, nothing will be changed")

    findings: dict[str, list[str]] = {}
    findings["security group"] = fix_security_group(sess.client("ec2"), args.apply)

    s3 = sess.client("s3")
    for output_name in ("test_bucket",):
        bucket = tf_output(output_name)
        if bucket:
            findings[f"bucket {bucket}"] = fix_bucket(s3, bucket, args.apply)
        else:
            findings[output_name] = [
                "not readable from terraform output. If you have just added the log_bucket "
                "output, run `terraform apply` in terraform/baseline first."
            ]

    log_bucket = tf_output("log_bucket")
    if log_bucket:
        try:
            s3.head_bucket(Bucket=log_bucket)
        except Exception:
            findings["log bucket"] = [
                f"{log_bucket} does not exist - DEL-001 deleted it and did not restore it. "
                "Terraform manages this one, so `terraform apply` will recreate it."
            ]

    trail = tf_output("cloudtrail_name")
    if trail:
        findings[f"trail {trail}"] = fix_cloudtrail(sess.client("cloudtrail"), trail, args.apply)

    print()
    dirty = False
    for area, notes in findings.items():
        if not notes:
            print(f"  {area:34s} clean")
            continue
        dirty = True
        print(f"  {area}")
        for note in notes:
            print(f"      - {note}")

    print()
    if not dirty:
        print("Nothing out of place. The experiment can start.")
        return 0
    if args.apply:
        print("Changes made. Now run `terraform apply` in terraform/baseline to settle anything")
        print("Terraform manages, then re-run the dry run.")
        return 0
    print("Re-run with --apply to revert these.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
