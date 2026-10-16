#!/usr/bin/env python3
"""Return the environment to the secure baseline after a scenario.

Runs terraform apply, then confirms with a refresh-only plan that nothing is left over.
A scenario is not finished until this reports zero drift - otherwise the next observation
starts from a contaminated baseline.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import parse_args, record  # noqa: E402

BASELINE = Path("terraform/baseline")

# Every resource this project creates carries these. If a stack does not look like the
# research baseline, this script must not apply to it.
EXPECTED_TAGS = {"Project": "TerraGuard-AI", "Environment": "test"}


def _run(args: list[str]) -> int:
    return subprocess.run(args, cwd=str(BASELINE), check=False).returncode


def _capture(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, check=False
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _drift_count() -> int | None:
    """Count drifted resources from the refresh-only plan JSON. None if Terraform failed.

    This replaced `-detailed-exitcode`. On 16 Oct, Terraform 1.16.5 printed "No changes" for a
    refresh-only plan and still exited 2, so the restore reported drift that did not exist.
    `resource_drift` in the plan JSON is the same evidence the scanner reads.
    """
    plan = BASELINE / "restore-check.tfplan"
    try:
        code, _ = _capture(
            ["terraform", "plan", "-refresh-only", "-input=false", f"-out={plan.name}"],
            cwd=BASELINE,
        )
        if code:
            return None
        code, out = _capture(["terraform", "show", "-json", plan.name], cwd=BASELINE)
        if code:
            return None
        return len(json.loads(out).get("resource_drift") or [])
    finally:
        plan.unlink(missing_ok=True)


def verify_target(profile: str, region: str) -> str | None:
    """Return a refusal reason, or None if this is safe to apply to.

    The runbook claimed this check existed and it did not. `terraform apply -auto-approve`
    against whatever credentials happen to be configured is the single most destructive thing
    in this repository, and it was running with no idea what it was pointed at.
    """
    code, out = _capture(
        ["aws", "sts", "get-caller-identity", "--profile", profile, "--output", "json"]
    )
    if code:
        return f"cannot identify the AWS account: {out.strip()[:200]}"
    try:
        arn = json.loads(out).get("Arn", "")
    except json.JSONDecodeError:
        return "could not parse the caller identity"
    if ":user/" not in arn:
        return f"refusing to apply as {arn or 'an unknown principal'}; use the IAM research user"

    if not (BASELINE / ".terraform").is_dir():
        return f"{BASELINE} is not initialised; run terraform init there first"

    code, out = _capture(["terraform", "show", "-json"], cwd=BASELINE)
    if code:
        return f"cannot read the current state: {out.strip()[:200]}"
    if out.strip():
        try:
            state = json.loads(out)
        except json.JSONDecodeError:
            return "state is not readable as JSON"
        values = json.dumps(state.get("values", {}))
        for key, want in EXPECTED_TAGS.items():
            if f'"{key}": "{want}"' not in values:
                return (
                    f"the state in {BASELINE} does not carry {key}={want}; "
                    "this does not look like the research baseline"
                )
    return None


def _resync_state(args) -> bool:
    """Clear a stale snapshot that the restore apply itself leaves behind.

    The first live SG-001 run on 16 Oct showed it. The apply reverted the managed ingress rule
    in AWS, but `aws_security_group.baseline` keeps a computed copy of its ingress list, and
    that copy was refreshed before the revert. The next refresh-only plan reported 0.0.0.0/0
    in state against 10.0.0.0/8 in AWS, with AWS already correct.

    A refresh-only apply would fix that, and it would also hide a real leftover by writing it
    into state. So it only runs after two independent checks agree nothing is left: a normal
    plan with no changes to make, and the API-side check in reset_aws_baseline.py.
    """
    if _run(["terraform", "plan", "-input=false", "-detailed-exitcode"]) != 0:
        return False
    reset = Path(__file__).resolve().parents[1] / "scripts" / "reset_aws_baseline.py"
    check = [sys.executable, str(reset), "--profile", args.profile, "--region", args.region]
    if subprocess.run(check, check=False).returncode != 0:
        return False
    if _run(["terraform", "apply", "-refresh-only", "-input=false", "-auto-approve"]) != 0:
        return False
    return _drift_count() == 0


def main() -> int:
    args = parse_args("RESTORE", __doc__)

    refusal = verify_target(args.profile, args.region)
    if refusal:
        record(args, "refused", {"reason": refusal})
        print(f"refusing to restore: {refusal}", file=sys.stderr)
        return 2

    if args.dry_run:
        record(args, "dry-run", {"action": "would apply baseline and re-check drift"})
        return 0

    if _run(["terraform", "apply", "-input=false", "-auto-approve"]) != 0:
        record(args, "restore-failed", {"stage": "apply"})
        return 1

    drifted = _drift_count()
    if drifted == 0:
        record(args, "restored", {"drift": "none"})
        return 0
    if drifted and _resync_state(args):
        record(args, "restored", {"drift": "none", "state_resync": True})
        return 0
    # This happened on 13 Oct and was written to a log nobody read, leaving an open 0.0.0.0/0
    # rule in place for a day. `terraform apply` cannot revert a change to something it does
    # not manage, so the message has to name the tool that can.
    record(args, "restore-incomplete", {"drifted_resources": drifted})
    sys.stderr.write(
        "RESTORE INCOMPLETE: drift remains after apply.\n"
        "terraform apply cannot revert a resource it does not manage (R25). Run:\n"
        "  python scripts/reset_aws_baseline.py --profile <profile> --apply\n"
        "and then terraform apply in terraform/baseline. Do not run further scenarios first.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
