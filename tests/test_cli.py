"""Phase 8/9: the command line and the severity gate.

The gate is the part that decides whether a pipeline goes red, so the exit codes are tested
as behaviour rather than assumed.
"""

from __future__ import annotations

import json

from terraguard.cli import main

STATE = json.dumps({"version": 4, "resources": []}, indent=2)
SECURE_BACKEND = """terraform {
  backend "s3" {
    bucket       = "example-state"
    key          = "env/terraform.tfstate"
    region       = "ap-southeast-2"
    encrypt      = true
    use_lockfile = true
  }
}
"""
OPEN_INGRESS = {
    "format_version": "1.2",
    "terraform_version": "1.11.0",
    "resource_drift": [
        {
            "address": "aws_vpc_security_group_ingress_rule.ssh",
            "mode": "managed",
            "type": "aws_vpc_security_group_ingress_rule",
            "name": "ssh",
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {
                "actions": ["update"],
                "before": {"cidr_ipv4": "10.0.0.0/8"},
                "after": {"cidr_ipv4": "0.0.0.0/0"},
                "before_sensitive": {},
                "after_sensitive": {},
            },
        }
    ],
}


def _dirty(tmp_path):
    (tmp_path / "terraform.tfstate").write_text(STATE, encoding="utf-8")
    (tmp_path / "backend.tf").write_text(SECURE_BACKEND, encoding="utf-8")
    return tmp_path


def _clean(tmp_path):
    (tmp_path / "backend.tf").write_text(SECURE_BACKEND, encoding="utf-8")
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    return tmp_path


def test_scan_finds_committed_state_outside_a_git_repository(tmp_path, capsys):
    """A directory that is not a repository used to scan clean, which looks like a pass."""
    assert main(["scan", str(_dirty(tmp_path))]) == 0
    assert "TG-P01" in capsys.readouterr().out


def test_scan_of_a_clean_directory_reports_nothing(tmp_path, capsys):
    main(["scan", str(_clean(tmp_path))])
    assert "No findings" in capsys.readouterr().out


def test_gate_fails_the_build_on_a_high_finding(tmp_path):
    assert main(["scan", str(_dirty(tmp_path)), "--fail-on", "high"]) == 1


def test_gate_passes_a_clean_directory(tmp_path):
    assert main(["scan", str(_clean(tmp_path)), "--fail-on", "high"]) == 0


def test_gate_threshold_is_respected(tmp_path):
    """Separate directories: _clean must not inherit the state file _dirty wrote."""
    dirty = tmp_path / "dirty"
    clean = tmp_path / "clean"
    dirty.mkdir()
    clean.mkdir()
    assert main(["scan", str(_dirty(dirty)), "--fail-on", "medium"]) == 1
    assert main(["scan", str(_clean(clean)), "--fail-on", "low"]) == 0


def test_indeterminate_controls_warn_rather_than_pass_silently(tmp_path, capsys):
    """The warning belongs on stderr; stdout has to stay parseable."""
    main(["scan", str(_clean(tmp_path)), "--include-optional"])
    assert "could not be assessed" in capsys.readouterr().err


def test_analyse_maps_drift_to_a_control(tmp_path, capsys):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(OPEN_INGRESS), encoding="utf-8")
    main(["analyse", "--plan-json", str(plan), "--include-optional"])
    out = capsys.readouterr().out
    assert "TG-P10" in out, "drift findings must carry the control they violate"


def test_json_report_is_valid_json(tmp_path, capsys):
    main(["scan", str(_dirty(tmp_path)), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["high_or_critical"] == 1


def test_csv_report_is_written_to_disk(tmp_path):
    out = tmp_path / "report.csv"
    main(["scan", str(_dirty(tmp_path)), "--format", "csv", "--output", str(out)])
    assert out.exists()
    assert "finding_id" in out.read_text(encoding="utf-8").splitlines()[0]


def test_scan_of_a_missing_directory_is_a_usage_error(tmp_path):
    assert main(["scan", str(tmp_path / "nope")]) == 2


def test_leak_prevention_demonstration_passes():
    """The end-to-end proof runs in CI, not just by hand.

    Detection counts over generated scenarios measure internal consistency. This asserts the
    claim that actually matters: a real credential is found, is never reprinted, and the
    commit carrying it does not land.
    """
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, str(root / "scripts/demo_leak_prevention.py")],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "8/8 checks passed" in proc.stdout


def test_fail_on_critical_can_actually_fail(tmp_path):
    """Regression: no band mapped to critical, so the strictest gate passed everything.

    The rubric merges high and critical, so this is an alias rather than a finer filter. An
    alias that fires is correct; a flag that silently never fires is not.
    """
    dirty = tmp_path / "dirty"
    clean = tmp_path / "clean"
    dirty.mkdir()
    clean.mkdir()
    assert main(["scan", str(_dirty(dirty)), "--fail-on", "critical"]) == 1
    assert main(["scan", str(_clean(clean)), "--fail-on", "critical"]) == 0
