"""Phase 2: raw diffs become security events, and only when they are regressions."""

from __future__ import annotations

import json
from pathlib import Path

from terraguard.drift_extractor import extract_from_plan
from terraguard.drift_normaliser import normalise, normalise_attribute, normalise_record
from terraguard.models import AttributeChange, ChangeAction, DriftRecord, NormalisedEvent

FIXTURE = Path(__file__).parent / "fixtures" / "plan_sg_drift.json"


def _chg(path, before, after, sensitive=False):
    return AttributeChange(
        path=path, before_category=before, after_category=after, sensitive=sensitive
    )


def test_opening_a_cidr_is_a_security_event():
    assert (
        normalise_attribute(_chg("cidr_ipv4", "restricted", "public"))
        is NormalisedEvent.PUBLIC_NETWORK_ACCESS
    )


def test_closing_a_cidr_is_not_reported():
    assert normalise_attribute(_chg("cidr_ipv4", "public", "restricted")) is None


def test_disabling_encryption_and_logging():
    assert (
        normalise_attribute(_chg("server_side_encryption", "enabled", "disabled"))
        is NormalisedEvent.ENCRYPTION_DISABLED
    )
    assert (
        normalise_attribute(_chg("enable_logging", "enabled", "disabled"))
        is NormalisedEvent.SECURITY_LOGGING_DISABLED
    )


def test_enabling_encryption_is_not_a_finding():
    assert normalise_attribute(_chg("server_side_encryption", "disabled", "enabled")) is None


def test_wildcard_privilege():
    assert (
        normalise_attribute(_chg("Statement.0.Action", "value", "wildcard"))
        is NormalisedEvent.PRIVILEGE_EXPANSION
    )


def test_tag_change_is_non_security():
    assert (
        normalise_attribute(_chg("tags.Owner", "value", "value"))
        is NormalisedEvent.OPERATIONAL_DRIFT
    )


def test_out_of_band_deletion_short_circuits_attributes():
    rec = DriftRecord(
        resource_address="aws_s3_bucket.test",
        resource_type="aws_s3_bucket",
        change_action=ChangeAction.DELETE,
        is_remote_drift=True,
        changed_attributes=[_chg("tags.Owner", "value", "absent")],
    )
    findings = normalise_record(rec)
    assert len(findings) == 1
    assert findings[0].normalised_event is NormalisedEvent.OUT_OF_BAND_DELETION


def test_planned_deletion_is_not_out_of_band():
    rec = DriftRecord(
        resource_address="aws_s3_bucket.test",
        resource_type="aws_s3_bucket",
        change_action=ChangeAction.DELETE,
        is_remote_drift=False,
    )
    assert normalise_record(rec) == []


def test_fixture_yields_one_public_access_event_and_one_operational():
    plan = json.loads(FIXTURE.read_text(encoding="utf-8"))
    findings = normalise(extract_from_plan(plan), scenario_id="SG-001")
    events = [f.normalised_event for f in findings]
    assert NormalisedEvent.PUBLIC_NETWORK_ACCESS in events
    assert NormalisedEvent.OPERATIONAL_DRIFT in events
    assert all(f.scenario_id == "SG-001" for f in findings)
