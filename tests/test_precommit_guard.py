"""The Phase 0 exit criterion: a deliberate state-file commit is refused."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK = REPO_ROOT / "scripts" / "check_no_state_files.py"


def _run(*paths: str, cwd: Path | None = None) -> int:
    return subprocess.run(
        [sys.executable, str(HOOK), *paths], cwd=str(cwd or REPO_ROOT), capture_output=True
    ).returncode


def test_blocks_tfstate():
    assert _run("infra/terraform.tfstate") == 1


def test_blocks_backup_and_saved_plan():
    assert _run("terraform.tfstate.backup") == 1
    assert _run("tfplan") == 1
    assert _run("environments/prod/tfplan.json") == 1


def test_allows_sanitised_fixtures():
    assert _run("tests/fixtures/plan_sg_drift.json") == 0
    assert _run("terraform/fixtures/exposed_state/terraform.tfstate") == 0


def test_blocks_aws_key_in_any_file(tmp_path):
    target = tmp_path / "config.txt"
    example_key = "AKIA" + "IOSFODNN7EXAMPLE"
    target.write_text(f"AWS_ACCESS_KEY_ID={example_key}\n", encoding="utf-8")
    assert _run("config.txt", cwd=tmp_path) == 1


def test_allows_ordinary_source():
    assert _run("terraguard/cli.py") == 0


def test_blocks_a_password_with_no_recognisable_shape(tmp_path):
    """The gap closed on 16 Oct: only the key name marks this value as a secret."""
    (tmp_path / "main.tf").write_text('db_password = "' + "hunter" + '2xyz"\n', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(HOOK), "main.tf"], cwd=str(tmp_path), capture_output=True, text=True
    )
    assert proc.returncode == 1
    assert "db_password" in proc.stderr
    assert "hunter2xyz" not in proc.stderr


def test_allows_a_password_reference(tmp_path):
    (tmp_path / "main.tf").write_text("db_password = var.db_password\n", encoding="utf-8")
    assert _run("main.tf", cwd=tmp_path) == 0


def test_every_tracked_file_passes_the_guard():
    """CI runs the guard over `git ls-files`, so the repository itself must pass it."""
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True
    ).stdout.split()
    assert _run(*tracked) == 0
