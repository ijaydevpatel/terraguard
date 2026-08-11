#!/usr/bin/env python3
"""SG-001 / SG-002 / SG-003: open an administrative port to the world, outside Terraform.

Adds a single ingress rule with boto3 so Terraform has no knowledge of it. That is what
makes it drift rather than a configuration change.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record, require, session  # noqa: E402

PORTS = {"SG-001": 22, "SG-002": 3389, "SG-003": 22}


def main() -> int:
    args = parse_args("SG-001", __doc__)
    port = PORTS.get(args.scenario_id, 22)
    ipv6 = args.scenario_id == "SG-003"
    ec2 = session(args).client("ec2")

    groups = ec2.describe_security_groups(
        Filters=[{"Name": "tag:TerraGuardRole", "Values": ["drift-target"]}]
    )["SecurityGroups"]
    require(
        len(groups) == 1, f"expected exactly one drift-target security group, found {len(groups)}"
    )
    sg = groups[0]

    open_cidr = "::/0" if ipv6 else "0.0.0.0/0"
    already = any(
        any(
            r.get("CidrIpv6" if ipv6 else "CidrIp") == open_cidr
            for r in perm.get("Ipv6Ranges" if ipv6 else "IpRanges", [])
        )
        for perm in sg.get("IpPermissions", [])
    )
    require(not already, "the group is already open to the world; baseline is not clean")

    if args.dry_run:
        record(args, "dry-run", {"group_id": sg["GroupId"], "port": port, "cidr": open_cidr})
        return 0

    rng = (
        {"Ipv6Ranges": [{"CidrIpv6": open_cidr}]} if ipv6 else {"IpRanges": [{"CidrIp": open_cidr}]}
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port, **rng}],
    )
    record(args, "injected", {"group_id": sg["GroupId"], "port": port, "cidr": open_cidr})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
