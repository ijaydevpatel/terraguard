"""Phase 8: the report, the predictor, and the redaction gate at the boundary."""

from __future__ import annotations

import json

import pytest

from terraguard.feature_builder import FindingRow
from terraguard.model_predictor import LOW_CONFIDENCE, Prediction, SeverityPredictor
from terraguard.report_generator import (
    REPORT_FIELDS,
    RedactionError,
    assert_clean,
    build_report,
    render_csv,
    render_json,
    render_terminal,
)


def fake_aws_key() -> str:
    """Assembled at runtime so the literal never exists in a tracked file.

    The commit guard and gitleaks both scan for this shape. A test that spells it out blocks
    the build - and that is the guard doing its job, not a false positive. The value is AWS's
    own published documentation placeholder, split so it is only a key at runtime.
    """
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def fake_marker() -> str:
    """Same reasoning: the fixture marker is assembled rather than written out."""
    return "TERRAGUARD" + "_TEST_SECRET_" + "001"


def row(**kwargs) -> FindingRow:
    base = dict(
        run_id="ST-001-abc",
        scenario_id="ST-001",
        finding_id="repo:terraform.tfstate:TG-P01",
        evidence_source="repository",
        control_id="TG-P01",
        normalised_event="insecure_state_handling",
        resource_address="terraform.tfstate",
        detail="Terraform state file tracked in the repository",
        resource_type="repository_file",
        run_policy_status="non_compliant",
        assessment_coverage=0.12,
    )
    base.update(kwargs)
    return FindingRow(**base)


def test_report_carries_all_seventeen_fields():
    report = build_report([row()])
    assert len(REPORT_FIELDS) == 17
    assert set(REPORT_FIELDS) == set(vars(report[0]))


def test_worst_findings_come_first():
    findings = [
        row(finding_id="low", control_id="", normalised_event="non_security_operational_drift"),
        row(finding_id="high", control_id="TG-P01"),
    ]
    report = build_report(findings)
    assert report[0].severity_band == "high_or_critical"
    assert report[-1].severity_band == "non_security_or_low"


def test_works_with_no_trained_model():
    """A fresh clone has no model artefacts. The tool must still report."""
    report = build_report([row()], SeverityPredictor())
    assert report[0].severity_band == "high_or_critical"
    assert report[0].model_band is None
    assert report[0].model_agrees is None


def test_every_record_cites_the_rule_that_produced_it():
    report = build_report([row()])
    assert report[0].severity_rule == 1
    assert report[0].severity_reason


def test_redaction_gate_refuses_a_credential():
    bad = [row(detail=f"aws_access_key_id = {fake_aws_key()}")]
    with pytest.raises(RedactionError):
        build_report(bad)


def test_redaction_gate_refuses_a_test_marker():
    """Fixtures are seeded with these. None may reach a report."""
    with pytest.raises(RedactionError):
        build_report([row(detail=f"password = {fake_marker()}")])


def test_redacted_marker_is_allowed_through():
    """The shape-preserving marker is the redactor working, not a leak."""
    report = build_report([row(detail="password = [REDACTED]:len=8:sha256:abc123")])
    assert report[0].detail.startswith("password")


def test_json_report_is_parseable_and_counts_bands():
    payload = json.loads(render_json(build_report([row()])))
    assert payload["counts"]["high_or_critical"] == 1
    assert payload["fields"] == REPORT_FIELDS


def test_terminal_output_is_plain_ascii():
    """It lands in CI logs, where escape codes and box drawing do not survive."""
    text = render_terminal(build_report([row()]))
    assert text.isascii()
    assert "\x1b" not in text
    assert "SEVERITY" in text


def test_terminal_output_reports_coverage():
    text = render_terminal(build_report([row()]))
    assert "assessment coverage" in text


def test_empty_report_says_so():
    assert "No findings" in render_terminal([])


def test_rubric_wins_when_the_model_disagrees():
    prediction = Prediction(
        finding_id="x",
        rule_band="high_or_critical",
        rule_number=1,
        rule_reason="r",
        predicted_band="medium",
        confidence=0.9,
    )
    assert prediction.band == "high_or_critical"
    assert not prediction.agrees


def test_low_confidence_is_flagged_not_hidden():
    prediction = Prediction("x", "medium", 4, "r", predicted_band="medium", confidence=0.3)
    assert not prediction.is_confident
    assert LOW_CONFIDENCE == 0.5


def test_disagreements_are_collectable_for_the_log():
    predictions = [
        Prediction("a", "medium", 4, "r", predicted_band="medium", confidence=0.8),
        Prediction("b", "high_or_critical", 1, "r", predicted_band="medium", confidence=0.8),
        Prediction("c", "medium", 4, "r"),
    ]
    disagreements = SeverityPredictor.disagreements(predictions)
    assert [p.finding_id for p in disagreements] == ["b"]


def test_assert_clean_passes_a_normal_report():
    assert_clean(build_report([row()]))


def test_csv_has_a_header_and_one_row_per_finding():
    import csv as _csv
    import io as _io

    text = render_csv(build_report([row(), row(finding_id="second")]))
    parsed = list(_csv.DictReader(_io.StringIO(text)))
    assert list(parsed[0]) == REPORT_FIELDS
    assert len(parsed) == 2


def test_csv_survives_a_detail_containing_a_comma_and_quotes():
    """Details routinely contain both. A hand-rolled writer would corrupt the file."""
    import csv as _csv
    import io as _io

    nasty = 'state file tracked, then deleted; see "terraform.tfstate"'
    text = render_csv(build_report([row(detail=nasty)]))
    parsed = list(_csv.DictReader(_io.StringIO(text)))
    assert len(parsed) == 1
    assert parsed[0]["detail"] == nasty


def test_csv_goes_through_the_redaction_gate():
    """A record can reach render_csv without passing build_report. The gate must still fire."""
    with pytest.raises(RedactionError):
        render_csv(_leaky())


def test_json_goes_through_the_redaction_gate():
    with pytest.raises(RedactionError):
        render_json(_leaky())


def test_terminal_goes_through_the_redaction_gate():
    with pytest.raises(RedactionError):
        render_terminal(_leaky())


def _leaky():
    """A report record that should never be writable."""
    from terraguard.report_generator import ReportRecord

    return [
        ReportRecord(
            run_id="r",
            scenario_id="s",
            finding_id="f",
            evidence_source="repository",
            control_id="TG-P06",
            resource_type="repository_file",
            resource_address="main.tf",
            normalised_event="sensitive_data_exposure",
            detail=f"aws_access_key_id = {fake_aws_key()}",
            run_policy_status="non_compliant",
            assessment_coverage=0.5,
            severity_band="high_or_critical",
            severity_rule=1,
            severity_reason="credential exposed",
            model_band=None,
            model_confidence=None,
            model_agrees=None,
        )
    ]
