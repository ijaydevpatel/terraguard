"""Prove the tool detects a credential leak, refuses to echo it, and blocks the commit.

"Detection 684 of 684" is internal consistency: every generated scenario raised the control
its manifest named. It says nothing about whether a real credential gets caught and stopped.
This demonstration does, on a throwaway repository, in four steps:

    1. DETECT   plant an AWS key and a state file, scan, expect findings and exit 1
    2. REDACT   check the report never contains the key or the password it found
    3. PREVENT  install the guard as a pre-commit hook and confirm the commit does not land
    4. RECOVER  remove the secrets and confirm a clean commit goes through

Nothing here touches the project repository. Everything happens in a temporary directory that
is deleted afterwards.

    python scripts/demo_leak_prevention.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Assembled at runtime so no credential shape is ever a literal in a tracked file. The value
# is AWS's own published documentation placeholder.
FAKE_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
FAKE_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
FAKE_DB_PASSWORD = "Pr0d" + "DbPass!"

PROVIDERS = f"""provider "aws" {{
  region     = "ap-southeast-2"
  access_key = "{FAKE_KEY}"
  secret_key = "{FAKE_SECRET}"
}}
"""
STATE = (
    '{"version":4,"resources":[{"type":"aws_db_instance","instances":'
    '[{"attributes":{"password":"' + FAKE_DB_PASSWORD + '"}}]}]}'
)
HOOK = """#!/bin/sh
git diff --cached --name-only --diff-filter=ACM | xargs -r {python} {guard}
"""

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def record(step: str, ok: bool, detail: str) -> None:
    results.append((step, PASS if ok else FAIL, detail))
    print(f"  [{PASS if ok else FAIL}] {step}: {detail}")


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.name=demo", "-c", "user.email=demo@example.invalid", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )


def run_cli(repo: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    return subprocess.run(
        [sys.executable, "-m", "terraguard.cli", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
    )


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="terraguard-leak-demo-"))
    try:
        repo = workspace / "repo"
        repo.mkdir()
        git(repo, "init", "-q", ".")
        (repo / "providers.tf").write_text(PROVIDERS, encoding="utf-8")
        (repo / "terraform.tfstate").write_text(STATE, encoding="utf-8")
        git(repo, "add", "-A")

        print("\n1. DETECT")
        scan = run_cli(repo, "scan", ".", "--fail-on", "high")
        record(
            "key is found",
            "AWS access key id" in scan.stdout,
            "TG-P06 raised on providers.tf" if "AWS access key id" in scan.stdout else scan.stdout,
        )
        record(
            "state file is found",
            "TG-P01" in scan.stdout,
            "TG-P01 raised on terraform.tfstate",
        )
        record("gate fails the build", scan.returncode == 1, f"exit {scan.returncode}, expected 1")

        print("\n2. REDACT")
        report = run_cli(repo, "scan", ".", "--format", "json").stdout
        record("key is not echoed", FAKE_KEY not in report, "the value never appears in output")
        record(
            "password is not echoed",
            FAKE_DB_PASSWORD not in report,
            "only the key name and a character count are reported",
        )

        print("\n3. PREVENT")
        hooks = repo / ".git" / "hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        hook = hooks / "pre-commit"
        hook.write_text(
            HOOK.format(python=sys.executable, guard=ROOT / "scripts/check_no_state_files.py"),
            encoding="utf-8",
        )
        hook.chmod(0o755)
        git(repo, "commit", "-q", "-m", "add provider config")
        count = git(repo, "rev-list", "--count", "HEAD").stdout.strip() or "0"
        record("commit is blocked", count == "0", f"{count} commits in the repository")

        print("\n4. RECOVER")
        (repo / "terraform.tfstate").unlink()
        (repo / "providers.tf").write_text(
            'provider "aws" {\n  region = "ap-southeast-2"\n}\n', encoding="utf-8"
        )
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "add provider config")
        count = git(repo, "rev-list", "--count", "HEAD").stdout.strip() or "0"
        record("clean commit lands", count == "1", f"{count} commit in the repository")
        after = run_cli(repo, "scan", ".", "--fail-on", "high")
        record("scan is clean", after.returncode == 0, f"exit {after.returncode}, expected 0")

        failures = [r for r in results if r[1] == FAIL]
        print(f"\n{len(results) - len(failures)}/{len(results)} checks passed")
        if failures:
            print("FAILED: " + ", ".join(r[0] for r in failures))
            return 1
        print("The tool detects the credential, never reprints it, and stops the commit.")
        return 0
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
