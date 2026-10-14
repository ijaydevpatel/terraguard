#!/usr/bin/env python3
"""SG-001 / SG-002 / SG-003: widen administrative access to the world, outside Terraform.

This script used to call `authorize_security_group_ingress` to add a new open rule. That
looked like the obvious way to create drift and it does not work, which the first live dry run
exposed: the pre-flight reported the baseline clean while the group was already open to the
world, and both statements were true.

The baseline manages ingress as individual `aws_vpc_security_group_ingress_rule` resources, one
Terraform resource per rule. A rule added through the API has no state entry, so
`terraform plan -refresh-only` has nothing to reconcile it against and reports no changes. The
rule is wide open and invisible. Recorded as R25, and it is a real limitation of plan-based
drift detection rather than a bug in this project - any tool that reads refresh output inherits
it.

So the injection now *modifies the managed rule* instead: it rewrites the baseline SSH rule's
CIDR from the administrative range to 0.0.0.0/0 with `ModifySecurityGroupRules`. That rule is in
state, so refresh sees the change, and `terraform apply` restores it. Same posture regression,
same severity, and detectable - which is what a drift scenario has to be to produce evidence.

`--unmanaged` reproduces the old behaviour on purpose, to demonstrate the blind spot rather
than trip over it. Nothing restores it but this script's own reset, so it is not part of the
seven-scenario run.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402

PORTS = {"SG-001": 22, "SG-002": 3389, "SG-003": 22}
ADMIN_CIDR = "10.0.0.0/8"


def main() -> int:
    args = parse_args("SG-001", __doc__)
    port = PORTS.get(args.scenario_id, 22)
    ipv6 = args.scenario_id == "SG-003"
    open_cidr = "::/0" if ipv6 else "0.0.0.0/0"
    ec2 = session(args).client("ec2")

    groups = ec2.describe_security_groups(
        Filters=[{"Name": "tag:TerraGuardRole", "Values": ["drift-target"]}]
    )["SecurityGroups"]
    require(
        len(groups) == 1, f"expected exactly one drift-target security group, found {len(groups)}"
    )
    sg = groups[0]

    if getattr(args, "unmanaged", False):
        return _add_unmanaged_rule(ec2, args, sg, port, open_cidr, ipv6)

    # Find the managed rule by the CIDR the baseline sets, not by position. Rule ids change on
    # every apply, so matching on the id would need a lookup the restore cannot repeat.
    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [sg["GroupId"]]}]
    )["SecurityGroupRules"]
    managed = [
        r
        for r in rules
        if not r["IsEgress"] and r.get("CidrIpv4") == ADMIN_CIDR and r.get("FromPort") == 22
    ]
    require(
        len(managed) == 1,
        f"expected one managed SSH rule on {ADMIN_CIDR}, found {len(managed)}. "
        "If it is zero, the group has already drifted - run scripts/reset_aws_baseline.py.",
    )
    rule = managed[0]

    already = any(
        not r["IsEgress"] and r.get("CidrIpv6" if ipv6 else "CidrIpv4") == open_cidr for r in rules
    )
    require(not already, "the group is already open to the world; baseline is not clean")

    if args.dry_run:
        record(
            args,
            "dry-run",
            {
                "group_id": sg["GroupId"],
                "rule_id": rule["SecurityGroupRuleId"],
                "from": ADMIN_CIDR,
                "to": open_cidr,
                "port": port,
                "method": "modify-managed-rule",
            },
        )
        return 0

    ec2.modify_security_group_rules(
        GroupId=sg["GroupId"],
        SecurityGroupRules=[
            {
                "SecurityGroupRuleId": rule["SecurityGroupRuleId"],
                "SecurityGroupRule": {
                    "IpProtocol": "tcp",
                    "FromPort": port,
                    "ToPort": port,
                    ("CidrIpv6" if ipv6 else "CidrIpv4"): open_cidr,
                    "Description": "widened out of band by SG scenario",
                },
            }
        ],
    )
    record(
        args,
        "injected",
        {
            "group_id": sg["GroupId"],
            "rule_id": rule["SecurityGroupRuleId"],
            "change": f"SSH source widened from {ADMIN_CIDR} to {open_cidr}",
            "method": "modify-managed-rule",
        },
    )
    return 0


def _add_unmanaged_rule(ec2, args, sg, port, open_cidr, ipv6) -> int:
    """Demonstrate R25: a rule Terraform never created, which refresh-only cannot see.

    Kept because the negative result is worth reporting. Not part of the seven-scenario run,
    because `terraform apply` will not clean it up.
    """
    rng = (
        {"Ipv6Ranges": [{"CidrIpv6": open_cidr}]} if ipv6 else {"IpRanges": [{"CidrIp": open_cidr}]}
    )
    if args.dry_run:
        record(args, "dry-run", {"group_id": sg["GroupId"], "method": "add-unmanaged-rule"})
        return 0
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, **rng}],
    )
    record(
        args,
        "injected",
        {
            "group_id": sg["GroupId"],
            "change": f"added unmanaged ingress {open_cidr}:{port}",
            "method": "add-unmanaged-rule",
            "expected_detection": "none - refresh-only has no state entry for this rule",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
