"""Phase 3: the scanners, and the false-positive control that keeps them honest."""

from __future__ import annotations

from pathlib import Path

from terraguard.backend_scanner import parse_backend_block, scan_backend_config
from terraguard.models import EvidenceSource
from terraguard.repository_scanner import scan_paths
from terraguard.workflow_scanner import scan_workflow_file, scan_workflow_text

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "terraform" / "fixtures"


# ---------------------------------------------------------------- repository
def test_state_and_plan_files_are_flagged():
    findings = scan_paths(
        ["infra/terraform.tfstate", "terraform.tfstate.backup", "tfplan", "env/tfplan.json"]
    )
    controls = {f.control_id for f in findings}
    assert controls == {"TG-P01", "TG-P07"}
    assert len(findings) == 4


def test_ordinary_source_is_not_flagged():
    assert scan_paths(["terraguard/cli.py", "README.md", "terraform/baseline/s3.tf"]) == []


def test_fixtures_are_excluded_unless_asked_for():
    p = ["terraform/fixtures/exposed_state/terraform.tfstate"]
    assert scan_paths(p) == []
    assert len(scan_paths(p, include_fixtures=True)) == 1


def test_history_only_files_are_reported_distinctly():
    findings = scan_paths(["old/terraform.tfstate"], in_history_only={"old/terraform.tfstate"})
    assert findings[0].raw["in_history_only"] is True
    assert "history" in findings[0].detail


# ---------------------------------------------------------------- workflow
def test_insecure_workflow_fixture_trips_every_check():
    findings = scan_workflow_file(FIX / "insecure_workflow" / ".github" / "workflows" / "plan.yml")
    controls = {f.control_id for f in findings}
    assert {"TG-P06", "TG-P07", "TG-P08", "TG-P09"} <= controls


def test_clean_workflow_fixture_yields_nothing():
    findings = scan_workflow_file(FIX / "clean" / ".github" / "workflows" / "terraguard.yml")
    assert findings == [], [f.detail for f in findings]


def test_missing_permissions_block_is_flagged():
    text = "name: x\non: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    assert any(f.control_id == "TG-P08" for f in scan_workflow_text(text))


def test_unparseable_workflow_is_reported_not_ignored():
    findings = scan_workflow_text("jobs: [unclosed\n")
    assert len(findings) == 1


# ---------------------------------------------------------------- backend
def test_local_backend_is_non_compliant():
    text = (FIX / "insecure_backend" / "backend.tf").read_text(encoding="utf-8")
    findings = scan_backend_config(text)
    assert findings[0].control_id == "TG-P02"


def test_clean_backend_fixture_is_silent():
    text = (FIX / "clean" / "backend.tf").read_text(encoding="utf-8")
    assert scan_backend_config(text) == [], scan_backend_config(text)


def test_deprecated_dynamodb_locking_is_flagged():
    text = (
        'terraform {\n backend "s3" {\n bucket = "b"\n encrypt = true\n dynamodb_table = "t"\n }\n}'
    )
    details = " ".join(f.detail for f in scan_backend_config(text))
    assert "deprecated" in details


def test_missing_backend_block_means_local_state():
    assert scan_backend_config("terraform {\n}")[0].control_id == "TG-P02"


def test_backend_attributes_are_parsed():
    attrs = parse_backend_block((FIX / "clean" / "backend.tf").read_text(encoding="utf-8"))
    assert attrs["backend_type"] == "s3"
    assert attrs["use_lockfile"] == "true"


def test_every_scanner_emits_the_same_finding_shape():
    findings = (
        scan_paths(["a/terraform.tfstate"])
        + scan_workflow_text("jobs:\n  a:\n    steps:\n      - run: echo\n")
        + scan_backend_config("terraform {\n}")
    )
    for f in findings:
        assert isinstance(f.evidence_source, EvidenceSource)
        assert f.finding_id and f.control_id
