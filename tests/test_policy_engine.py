"""Phase 4: eight core controls, four outcomes, and no false assurance."""

from __future__ import annotations

from pathlib import Path

import pytest

from terraguard.models import EvidenceSource, Finding, PolicyStatus, Severity
from terraguard.policy_engine import assess, assessment_coverage, load_controls

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "policies"
ALL_SOURCES = set(EvidenceSource)


def test_catalogue_has_eight_core_controls():
    core = load_controls(POLICIES)
    assert len(core) == 8
    assert [c.id for c in core] == [f"TG-P0{i}" for i in range(1, 9)]


def test_optional_controls_are_opt_in():
    full = load_controls(POLICIES, include_optional=True)
    assert len(full) == 13  # TG-P13 added for out-of-band deletion
    assert {c.id for c in full} - {c.id for c in load_controls(POLICIES)} == {
        "TG-P09",
        "TG-P10",
        "TG-P11",
        "TG-P12",
        "TG-P13",
    }


def test_every_control_carries_a_citation_and_remediation():
    for c in load_controls(POLICIES, include_optional=True):
        assert c.source.strip(), f"{c.id} has no source"
        assert c.remediation.strip(), f"{c.id} has no remediation"
        assert isinstance(c.severity_if_violated, Severity)


def test_clean_evidence_gives_compliant():
    results = assess(load_controls(POLICIES), [], available_evidence=ALL_SOURCES)
    assert {r.status for r in results} == {PolicyStatus.COMPLIANT}
    assert assessment_coverage(results) == 1.0


def test_a_finding_makes_its_control_non_compliant():
    finding = Finding(
        finding_id="x",
        evidence_source=EvidenceSource.REPOSITORY,
        control_id="TG-P01",
        detail="state file tracked",
    )
    results = {
        r.control_id: r
        for r in assess(load_controls(POLICIES), [finding], available_evidence=ALL_SOURCES)
    }
    assert results["TG-P01"].status is PolicyStatus.NON_COMPLIANT
    assert results["TG-P02"].status is PolicyStatus.COMPLIANT


def test_missing_evidence_is_indeterminate_not_compliant():
    """The important one: absent evidence must never read as a pass."""
    results = {
        r.control_id: r
        for r in assess(load_controls(POLICIES), [], available_evidence={EvidenceSource.REPOSITORY})
    }
    assert results["TG-P01"].status is PolicyStatus.COMPLIANT
    assert results["TG-P08"].status is PolicyStatus.INDETERMINATE
    assert "no workflow evidence" in results["TG-P08"].reason


def test_unreadable_evidence_is_indeterminate():
    finding = Finding(
        finding_id="x",
        evidence_source=EvidenceSource.AWS_API,
        control_id="TG-P05",
        detail="could not determine",
        raw={"indeterminate": True},
    )
    results = {
        r.control_id: r
        for r in assess(load_controls(POLICIES), [finding], available_evidence=ALL_SOURCES)
    }
    assert results["TG-P05"].status is PolicyStatus.INDETERMINATE


def test_coverage_falls_when_answers_are_indeterminate():
    results = assess(load_controls(POLICIES), [], available_evidence={EvidenceSource.REPOSITORY})
    assert 0.0 < assessment_coverage(results) < 1.0


def test_duplicate_control_ids_are_rejected(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "controls:\n"
        "  - {id: TG-P01, name: a, evidence_source: repository}\n"
        "  - {id: TG-P01, name: b, evidence_source: repository}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_controls(tmp_path)


def test_not_applicable_is_returned_when_the_subject_does_not_exist():
    """The fourth outcome was defined and never reachable.

    A control about IAM read as compliant on a plan containing no IAM at all, which is false
    assurance arriving by a different route than the one `indeterminate` closes.
    """
    from terraguard.models import EvidenceSource, PolicyStatus
    from terraguard.policy_engine import assess, load_controls

    controls = load_controls(POLICIES, include_optional=True)
    results = assess(
        controls,
        [],
        available_evidence={EvidenceSource.TERRAFORM_PLAN_JSON},
        observed_resource_types={"aws_s3_bucket"},
    )
    by_id = {r.control.id: r.status for r in results}
    assert by_id["TG-P11"] is PolicyStatus.NOT_APPLICABLE
    assert by_id["TG-P12"] is not PolicyStatus.NOT_APPLICABLE


def test_applicability_is_skipped_when_the_inventory_is_unknown():
    """A caller that cannot enumerate resources must not be forced to invent one."""
    from terraguard.models import EvidenceSource, PolicyStatus
    from terraguard.policy_engine import assess, load_controls

    results = assess(
        load_controls(POLICIES, include_optional=True),
        [],
        available_evidence={EvidenceSource.TERRAFORM_PLAN_JSON},
    )
    assert all(r.status is not PolicyStatus.NOT_APPLICABLE for r in results)
