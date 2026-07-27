"""The offline path must work with no Terraform binary and no AWS credentials."""
from __future__ import annotations

import json
from pathlib import Path

from terraguard import redactor
from terraguard.evidence_collector import (
    collect_backend_config,
    collect_from_plan_json,
    collect_workflow_evidence,
)

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_offline_bundle_produces_only_sanitised_artefact(tmp_path):
    bundle = collect_from_plan_json(
        FIXTURES / "plan_sg_drift.json", tmp_path, repo_root=REPO_ROOT, scenario_id="SG-001"
    )
    assert bundle.scenario_id == "SG-001"
    assert bundle.plan_json_path is None, "raw plan JSON must never be retained"

    sanitised = Path(bundle.plan_json_sanitised_path)
    assert sanitised.exists()
    redactor.assert_clean(sanitised.read_text(encoding="utf-8"))

    plan = json.loads(sanitised.read_text(encoding="utf-8"))
    assert plan["terraguard"]["redacted"] is True
    assert plan["resource_drift"][0]["change"]["after"]["cidr_ipv4"] == "0.0.0.0/0"


def test_bundle_records_timing(tmp_path):
    bundle = collect_from_plan_json(FIXTURES / "plan_sg_drift.json", tmp_path)
    assert bundle.duration_ms is not None and bundle.duration_ms >= 0


def test_workflow_evidence_finds_repo_workflows():
    files = collect_workflow_evidence(REPO_ROOT)
    assert any("ci.yml" in f for f in files)


def test_backend_config_captured_from_insecure_fixture():
    raw = collect_backend_config(REPO_ROOT / "terraform" / "fixtures" / "insecure_backend")
    assert raw is not None
    assert 'backend "local"' in raw
