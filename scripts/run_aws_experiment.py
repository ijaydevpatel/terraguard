"""Run every AWS drift scenario end to end, with a restore and a clean check between each.

One command instead of forty, because the manual sequence is where mistakes happen: an
injection left in place, a plan JSON left on disk, a scenario recorded against the wrong run id.

For each scenario it:

    1. confirms the baseline is clean before touching anything
    2. injects the change through the AWS API, never through Terraform
    3. captures a refresh-only plan and converts it to JSON
    4. records the observation through the normal harness, so the row is produced the same way
       every other row in the dataset was
    5. restores the baseline and confirms the plan is clean again
    6. deletes the plan JSON, which holds every attribute of every resource in cleartext

It stops at the first failure and leaves the environment restored. A scenario that cannot be
cleaned up is worse than a scenario that was never run.

    python scripts/run_aws_experiment.py --profile default
    python scripts/run_aws_experiment.py --profile default --only SG-001
    python scripts/run_aws_experiment.py --profile default --dry-run
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "terraform" / "baseline"
EVIDENCE = ROOT / "evidence"
LOG = ROOT / "build" / "aws_experiment_log.txt"

# scenario id -> injection script. The ids match datasets/scenario_catalogue.csv, so the rows
# this produces join to the manifests written before any of it ran.
SCENARIOS: list[tuple[str, str]] = [
    ("SG-001", "inject_security_group_drift.py"),
    ("S3-001", "inject_s3_encryption_drift.py"),
    ("S3-002", "inject_s3_public_access.py"),
    ("IAM-001", "inject_iam_privilege_drift.py"),
    ("LOG-001", "inject_logging_drift.py"),
    ("TAG-001", "inject_tag_drift.py"),
    ("DEL-001", "delete_managed_resource.py"),
]

_lines: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)
    _lines.append(text)
    LOG.parent.mkdir(exist_ok=True)
    LOG.write_text("\n".join(_lines), encoding="utf-8")


def run(args: list[str], *, cwd: Path = ROOT, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)


def terraform_is_clean() -> tuple[bool, str]:
    proc = run(["terraform", "plan", "-refresh-only", "-no-color", "-input=false"], cwd=BASELINE)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        return False, out.strip()[-500:]
    return ("No changes" in out or "no differences" in out), out.strip()[-300:]


def capture_plan(destination: Path) -> bool:
    plan = BASELINE / "drift.tfplan"
    if run(
        ["terraform", "plan", "-refresh-only", "-no-color", "-input=false", "-out=drift.tfplan"],
        cwd=BASELINE,
    ).returncode:
        return False
    shown = run(["terraform", "show", "-json", "drift.tfplan"], cwd=BASELINE)
    plan.unlink(missing_ok=True)
    if shown.returncode:
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(shown.stdout, encoding="utf-8")
    return True


def restore(profile: str, run_id: str) -> bool:
    proc = run(
        [
            sys.executable,
            str(ROOT / "scenarios" / "restore_baseline.py"),
            "--run-id",
            run_id,
            "--profile",
            profile,
        ]
    )
    if proc.returncode:
        say(f"    restore failed: {(proc.stdout + proc.stderr).strip()[-400:]}")
    return proc.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="default")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--only", help="run a single scenario id")
    parser.add_argument("--dry-run", action="store_true", help="verify targets, change nothing")
    args = parser.parse_args()

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    say(f"TerraGuard AWS experiment  {stamp}  profile={args.profile} region={args.region}")

    identity = run(
        ["aws", "sts", "get-caller-identity", "--profile", args.profile, "--output", "json"]
    )
    if identity.returncode:
        say("cannot reach AWS. Check `aws configure` and the profile name.")
        return 2
    who = json.loads(identity.stdout)
    say(f"identity: {who.get('Arn', 'unknown')}")
    if ":user/" not in who.get("Arn", ""):
        say("refusing to run: this is not an IAM user. Do not run experiments as root.")
        return 2

    say("\n=== pre-flight: baseline must be clean before anything is injected")
    clean, detail = terraform_is_clean()
    if not clean:
        say("baseline is NOT clean. Resolve the existing drift first:\n" + detail)
        return 1
    say("  clean")

    scenarios = [s for s in SCENARIOS if not args.only or s[0] == args.only]
    if not scenarios:
        say(f"no scenario matching {args.only}")
        return 2

    results: list[dict] = []
    halt = False
    for scenario_id, script in scenarios:
        if halt:
            break
        run_id = f"{scenario_id}-{stamp}"
        say(f"\n=== {scenario_id}  ({script})")

        inject = [
            sys.executable,
            str(ROOT / "scenarios" / script),
            "--run-id",
            run_id,
            "--profile",
            args.profile,
            "--region",
            args.region,
        ]
        if args.dry_run:
            inject.append("--dry-run")
        proc = run(inject)
        say(f"  inject exit {proc.returncode}: {(proc.stdout or proc.stderr).strip()[:220]}")
        if proc.returncode:
            say("  injection failed; nothing to restore, moving on")
            results.append({"scenario": scenario_id, "status": "inject_failed"})
            continue
        if args.dry_run:
            results.append({"scenario": scenario_id, "status": "dry_run"})
            continue

        time.sleep(3)  # let the API change settle before refreshing
        evidence = EVIDENCE / f"{run_id}.json"
        try:
            if not capture_plan(evidence):
                say("  could not capture the refresh-only plan")
                results.append({"scenario": scenario_id, "status": "plan_failed"})
                continue
            say(f"  captured {evidence.name} ({evidence.stat().st_size} bytes)")

            recorded = run(
                [
                    sys.executable,
                    str(ROOT / "scenarios" / "run_experiment.py"),
                    scenario_id,
                    "--plan-json",
                    str(evidence),
                ]
            )
            say(f"  record exit {recorded.returncode}: {recorded.stdout.strip()[:220]}")

            assessed = run(
                [
                    sys.executable,
                    "-m",
                    "terraguard.cli",
                    "analyse",
                    "--plan-json",
                    str(evidence),
                    "--include-optional",
                    "--fail-on",
                    "high",
                ]
            )
            say("  " + "\n  ".join(assessed.stdout.strip().splitlines()[:6]))
            say(f"  gate exit {assessed.returncode}")
            results.append(
                {
                    "scenario": scenario_id,
                    "status": "ok",
                    "gate_exit": assessed.returncode,
                    "recorded": recorded.returncode == 0,
                }
            )
        finally:
            # Always restore, and always remove the plan JSON. It holds every attribute of
            # every refreshed resource in cleartext, which is the artefact TG-P07 warns about.
            restored = restore(args.profile, run_id)
            evidence.unlink(missing_ok=True)
            clean, detail = terraform_is_clean()
            say(f"  restored={restored} clean={clean}")
            if not clean:
                say("  STOPPING: baseline did not come back clean.\n" + detail)
                say("  Fix this before running anything else: `terraform apply` in the baseline.")
                halt = True

    say("\n=== summary")
    for r in results:
        say(f"  {r['scenario']:9s} {r['status']:14s} {r}")
    say(f"\nlog: {LOG}")
    say("Run `python -m terraguard.cli evaluate` to see the dataset with these rows included.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
