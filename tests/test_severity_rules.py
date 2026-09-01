"""Phase 6: the deterministic baseline. Frozen before any model is trained."""

from __future__ import annotations

from terraguard.models import EvidenceSource, Finding, NormalisedEvent, Severity
from terraguard.severity_rules import (
    HIGH_OR_CRITICAL,
    MEDIUM,
    NON_SECURITY_OR_LOW,
    RULES,
    classify,
    classify_all,
)


def f(control=None, event=None, detail=""):
    return Finding(
        finding_id="x",
        evidence_source=EvidenceSource.REPOSITORY,
        control_id=control,
        normalised_event=event,
        detail=detail,
    )


def test_every_label_cites_a_rule_that_exists():
    for finding in (
        f("TG-P01", NormalisedEvent.INSECURE_STATE_HANDLING),
        f("TG-P10", NormalisedEvent.PUBLIC_NETWORK_ACCESS),
        f("TG-P04", NormalisedEvent.INSECURE_STATE_HANDLING),
        f(None, NormalisedEvent.OPERATIONAL_DRIFT),
    ):
        assert classify(finding).rule in RULES


def test_rule_1_data_or_credentials_exposed():
    assert classify(f("TG-P01", NormalisedEvent.INSECURE_STATE_HANDLING)).band == HIGH_OR_CRITICAL
    assert classify(f("TG-P06", NormalisedEvent.SENSITIVE_DATA_EXPOSURE)).band == HIGH_OR_CRITICAL
    assert classify(f("TG-P12", NormalisedEvent.ENCRYPTION_DISABLED)).band == HIGH_OR_CRITICAL


def test_rule_2_access_granted():
    assert classify(f("TG-P10", NormalisedEvent.PUBLIC_NETWORK_ACCESS)).band == HIGH_OR_CRITICAL
    assert classify(f("TG-P11", NormalisedEvent.PRIVILEGE_EXPANSION)).band == HIGH_OR_CRITICAL


def test_rule_3_splits_on_whether_another_control_covers_it():
    """A trail is the only audit record. Bucket access logging is not, while it runs."""
    sole = f("TG-P12", NormalisedEvent.SECURITY_LOGGING_DISABLED, "trail logging stopped")
    covered = f("TG-P12", NormalisedEvent.SECURITY_LOGGING_DISABLED, "s3_access_logging disabled")
    assert classify(sole).band == HIGH_OR_CRITICAL
    assert classify(covered).band == MEDIUM
    assert classify(covered).rule == 3


def test_rule_4_secondary_defences_are_medium():
    assert classify(f("TG-P04", NormalisedEvent.INSECURE_STATE_HANDLING)).band == MEDIUM
    assert classify(f("TG-P08", NormalisedEvent.PRIVILEGE_EXPANSION)).band == MEDIUM


def test_rule_5_operational_drift_is_not_a_security_finding():
    label = classify(f(None, NormalisedEvent.OPERATIONAL_DRIFT))
    assert label.band == NON_SECURITY_OR_LOW
    assert label.rule == 5


def test_out_of_band_deletion_overrides_the_ladder():
    """Not because the resource mattered - because state and reality have diverged."""
    label = classify(f(None, NormalisedEvent.OUT_OF_BAND_DELETION))
    assert label.band == HIGH_OR_CRITICAL
    assert "diverge" in label.reason


def test_token_scope_is_medium_not_privilege_expansion():
    """TG-P08 is a privilege event but a secondary defence; rule 4 must win over rule 2."""
    assert classify(f("TG-P08", NormalisedEvent.PRIVILEGE_EXPANSION)).rule == 4


def test_all_three_bands_are_reachable():
    bands = {
        classify(f("TG-P01", NormalisedEvent.INSECURE_STATE_HANDLING)).band,
        classify(f("TG-P04", NormalisedEvent.INSECURE_STATE_HANDLING)).band,
        classify(f(None, NormalisedEvent.OPERATIONAL_DRIFT)).band,
    }
    assert bands == {HIGH_OR_CRITICAL, MEDIUM, NON_SECURITY_OR_LOW}


def test_severity_property_maps_to_the_enum():
    assert classify(f("TG-P01", NormalisedEvent.INSECURE_STATE_HANDLING)).severity is Severity.HIGH
    assert classify(f(None, NormalisedEvent.OPERATIONAL_DRIFT)).severity is Severity.LOW


def test_classify_all_preserves_order():
    findings = [
        f("TG-P01", NormalisedEvent.INSECURE_STATE_HANDLING),
        f(None, NormalisedEvent.OPERATIONAL_DRIFT),
    ]
    assert [x.band for x in classify_all(findings)] == [HIGH_OR_CRITICAL, NON_SECURITY_OR_LOW]
