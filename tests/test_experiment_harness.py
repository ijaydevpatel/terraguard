"""Phase 5/6: the harness must not let ground truth leak into detection."""

from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scenarios" / "run_experiment.py"
OBS = ROOT / "datasets" / "observations.csv"
DICT = ROOT / "datasets" / "data_dictionary.csv"

OFFLINE = ["ST-001", "ST-002", "WF-001", "BK-001", "CLEAN-001", "CLEAN-002"]


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HARNESS), *args], cwd=str(ROOT), capture_output=True, text=True
    )


def test_offline_scenarios_match_their_manifests():
    proc = _run(*OFFLINE, "--dry-run")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "MISS" not in proc.stdout


def test_a_run_without_a_manifest_is_refused():
    proc = _run("NOPE-999", "--dry-run")
    assert proc.returncode != 0
    assert "manifest" in (proc.stdout + proc.stderr)


def test_drift_scenario_without_a_plan_is_refused_not_guessed():
    """SG-001 needs a deployed baseline. It must fail loudly, not produce an empty row."""
    proc = _run("SG-001", "--dry-run")
    assert proc.returncode != 0
    assert "plan" in (proc.stdout + proc.stderr).lower()


def test_dry_run_writes_nothing(tmp_path):
    before = OBS.read_bytes() if OBS.exists() else b""
    _run("CLEAN-001", "--dry-run")
    after = OBS.read_bytes() if OBS.exists() else b""
    assert before == after


@pytest.mark.skipif(not OBS.exists(), reason="pilot has not been run")
def test_pilot_observations_are_well_formed():
    rows = list(csv.DictReader(OBS.open(encoding="utf-8")))
    assert rows, "observations.csv is empty"
    assert len({r["run_id"] for r in rows}) == len(rows), "duplicate run_id"
    for r in rows:
        assert r["scenario_id"]
        assert r["expected_policy_status"] in ("compliant", "non_compliant")
        assert 0.0 <= float(r["assessment_coverage"]) <= 1.0
        assert float(r["processing_time_ms"]) > 0


@pytest.mark.skipif(not OBS.exists(), reason="pilot has not been run")
def test_clean_controls_raise_no_findings():
    """The false-alert rate. A scanner that flags a clean repository gets switched off."""
    rows = [
        r
        for r in csv.DictReader(OBS.open(encoding="utf-8"))
        if r["scenario_group"] == "clean_control"
    ]
    assert rows
    assert all(int(r["findings_count"]) == 0 for r in rows)


@pytest.mark.skipif(not OBS.exists(), reason="pilot has not been run")
def test_repository_only_evidence_lowers_coverage():
    """Missing evidence must reduce coverage, not silently pass as compliant."""
    rows = {r["scenario_id"]: r for r in csv.DictReader(OBS.open(encoding="utf-8"))}
    assert float(rows["ST-001"]["assessment_coverage"]) < 0.5
    assert float(rows["CLEAN-001"]["assessment_coverage"]) > 0.5


def test_data_dictionary_covers_every_observation_column():
    fields = {r["field"] for r in csv.DictReader(DICT.open(encoding="utf-8"))}
    header = OBS.open(encoding="utf-8").readline().strip().split(",")
    assert set(header) <= fields, set(header) - fields
