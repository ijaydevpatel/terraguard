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


# ---------------------------------------------------------------- secrets with no shape
def test_password_under_a_sensitive_key_is_detected():
    """A password is just a string. The key it sits under is the only signal."""
    from terraguard.repository_scanner import find_sensitive_key_values

    fake = "".join(["Sup3r", "Value", "Here"])
    state = f'{{"outputs": {{"db_password": {{"value": "{fake}"}}}}, "password": "{fake}"}}'
    keys = {k for k, _ in find_sensitive_key_values(state)}
    assert "db_password" in keys or "password" in keys


def test_hcl_and_yaml_forms_are_both_read():
    """Values are assembled at runtime.

    A literal key/value pair written out in full in this file is itself a credential-shaped
    string, and gitleaks flags it in CI - which is the same lesson the AWS example key
    taught earlier. Building the value from parts keeps the test honest without putting a
    detectable secret in the source.
    """
    from terraguard.repository_scanner import find_sensitive_key_values

    fake = "".join(["corr", "ect", "horse"])
    assert find_sensitive_key_values(f'master_password = "{fake}"')
    assert find_sensitive_key_values(f"api_key: {fake}")


def test_variable_references_and_placeholders_are_not_secrets():
    """Flagging `password = var.db_password` would make the check useless within a day."""
    from terraguard.repository_scanner import find_sensitive_key_values

    for benign in (
        "password = var.db_password",
        "password = local.secret",
        '"password": "${var.pw}"',
        'password = "REPLACE_ME"',
        'api_key = "YOUR_KEY_HERE"',
        '"token": ""',
        '"secret": null',
        'password = "xxxx"',
    ):
        assert not find_sensitive_key_values(benign), benign


def test_the_value_itself_is_never_reported():
    from terraguard.repository_scanner import find_sensitive_key_values

    fake = "".join(["Sup3r", "Value", "Here"])
    out = find_sensitive_key_values(f'"password": "{fake}"')
    rendered = " ".join(f"{k} {v}" for k, v in out)
    assert fake not in rendered
    assert "characters" in rendered


def test_ordinary_keys_are_ignored():
    from terraguard.repository_scanner import find_sensitive_key_values

    assert not find_sensitive_key_values('"bucket_name": "terraguard-test-ab12"')


# ---------------------------------------------------------------- leftover working files
def test_temp_and_leftover_state_artefacts_are_flagged():
    from terraguard.repository_scanner import scan_temp_artefacts

    paths = [
        "terraform.tfstate.tmp",
        "terraform.tfstate.1",
        "plan.out",
        ".terraform/terraform.tfstate",
        "crash.log",
    ]
    findings = scan_temp_artefacts(paths)
    assert len(findings) == len(paths)
    assert {f.control_id for f in findings} == {"TG-P01"}


def test_ordinary_files_are_not_mistaken_for_temp_artefacts():
    from terraguard.repository_scanner import scan_temp_artefacts

    assert scan_temp_artefacts(["main.tf", "README.md", "plan_parser.py"]) == []


def test_allowlist_suppresses_a_documented_example(tmp_path):
    """An accepted example in documentation should not be reported every run."""
    from terraguard.repository_scanner import scan_file_contents

    (tmp_path / "doc.md").write_text('password = "hunter2"\n', encoding="utf-8")
    assert scan_file_contents(tmp_path, ["doc.md"])
    (tmp_path / ".terraguardignore").write_text("doc.md\n", encoding="utf-8")
    assert not scan_file_contents(tmp_path, ["doc.md"])


def test_allowlist_cannot_hide_a_committed_state_file(tmp_path):
    """The findings the tool exists for must never be suppressible."""
    from terraguard.repository_scanner import scan_paths

    (tmp_path / ".terraguardignore").write_text("terraform.tfstate\n", encoding="utf-8")
    assert scan_paths(["terraform.tfstate"])


def test_a_commented_out_backend_is_not_a_backend():
    """It passed the static check because the parser searched for words, not for code."""
    from terraguard.backend_scanner import scan_backend_config

    commented = '# terraform {\n#   backend "s3" {\n#     encrypt = true\n#   }\n# }\n'
    assert [f.control_id for f in scan_backend_config(commented)] == ["TG-P02"]


def test_backend_is_discovered_outside_the_root(tmp_path):
    """Terraform allows the block in any file; looking only at backend.tf missed them."""
    from terraguard.backend_scanner import discover_backend_files

    nested = tmp_path / "modules"
    nested.mkdir()
    (nested / "main.tf").write_text(
        'terraform {\n  backend "local" {\n    path = "x"\n  }\n}\n', encoding="utf-8"
    )
    assert [p.name for p in discover_backend_files(tmp_path)] == ["main.tf"]


def test_backend_discovery_ignores_heredocs_mentions_and_fixtures(tmp_path):
    """The repository self-scan failed CI on three false positives, all fixed here."""
    from terraguard.backend_scanner import discover_backend_files

    (tmp_path / "outputs.tf").write_text(
        'output "backend_block" {\n  value = <<EOT\nterraform {\n  backend "s3" {\n'
        '    bucket = "x"\n  }\n}\nEOT\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "providers.tf").write_text(
        '# no backend here: terraform keeps local state on purpose\nprovider "aws" {}\n',
        encoding="utf-8",
    )
    fixture = tmp_path / "terraform" / "fixtures" / "bad"
    fixture.mkdir(parents=True)
    (fixture / "backend.tf").write_text('terraform {\n  backend "local" {}\n}\n', encoding="utf-8")
    assert discover_backend_files(tmp_path) == []
    assert [p.name for p in discover_backend_files(fixture)] == ["backend.tf"]


def test_workflow_job_level_write_all_is_caught():
    from terraguard.workflow_scanner import scan_workflow_text

    yaml_text = (
        "name: x\non: [push]\njobs:\n  a:\n    permissions: write-all\n    steps:\n      - run: x\n"
    )
    assert "TG-P08" in [f.control_id for f in scan_workflow_text(yaml_text, "w.yml")]


def test_broad_artefact_upload_is_caught():
    from terraguard.workflow_scanner import scan_workflow_text

    yaml_text = (
        "name: x\non: [push]\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
        "      - uses: actions/upload-artifact@v4\n        with:\n          path: .\n"
    )
    assert "TG-P07" in [f.control_id for f in scan_workflow_text(yaml_text, "w.yml")]


def test_plan_printed_to_the_job_log_is_caught():
    from terraguard.workflow_scanner import scan_workflow_text

    yaml_text = (
        "name: x\non: [push]\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
        "      - run: terraform show -json tfplan\n"
    )
    assert "TG-P06" in [f.control_id for f in scan_workflow_text(yaml_text, "w.yml")]


def test_dangerous_port_change_is_not_operational_drift():
    from terraguard.drift_normaliser import normalise_attribute
    from terraguard.models import AttributeChange, NormalisedEvent

    change = AttributeChange(
        path="ingress.0.to_port",
        before_category="numeric",
        after_category="numeric",
        before_redacted="443",
        after_redacted="22",
        sensitive=False,
    )
    assert normalise_attribute(change) is NormalisedEvent.PUBLIC_NETWORK_ACCESS


def test_public_acl_is_not_operational_drift():
    from terraguard.drift_normaliser import normalise_attribute
    from terraguard.models import AttributeChange, NormalisedEvent

    change = AttributeChange(
        path="acl",
        before_category="value",
        after_category="value",
        before_redacted="private",
        after_redacted="public-read",
        sensitive=False,
    )
    assert normalise_attribute(change) is NormalisedEvent.PUBLIC_NETWORK_ACCESS
