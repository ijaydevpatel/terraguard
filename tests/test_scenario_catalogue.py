"""Phase 5: the catalogue and its manifests must agree, before any run happens."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "datasets" / "scenario_catalogue.csv"
MANIFESTS = ROOT / "datasets" / "scenario_manifests"


def rows() -> list[dict]:
    with CATALOGUE.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_catalogue_has_enough_core_templates_to_train_on():
    """The W7 rebalance raised the ceiling from 12.

    The 10-12 ceiling came from an hours argument during the 100-hour rescope, when every
    template meant hand-built fixtures. The generated families cost seconds of CPU and no AWS
    time at all, so that argument does not constrain them. What still matters is the number
    of independent groups per class, which the test below enforces.
    """
    core = [r for r in rows() if r["tier"] == "core"]
    assert 40 <= len(core) <= 200


def test_aws_bound_observations_stay_inside_the_time_budget():
    """The 60-100 band was always a budget on AWS time, not on rows.

    Generated families run offline in milliseconds, so applying that ceiling to them would
    be cargo-culting the number. It still binds the templates that need a deployed baseline,
    because those cost real minutes and real money.
    """
    aws_bound = sum(
        int(r["planned_variations"])
        for r in rows()
        if r["tier"] == "core" and r["needs_aws"].strip().lower() == "true"
    )
    assert aws_bound <= 100, aws_bound


def test_the_corpus_is_large_enough_to_train_on():
    core = sum(int(r["planned_variations"]) for r in rows() if r["tier"] == "core")
    assert core >= 300, core


def test_every_severity_class_has_at_least_three_independent_templates():
    """Group-aware CV splits on templates, not rows.

    A class with two templates cannot be split three ways, so more runs of the same scenario
    would not help. This is the check the class audit should have been from the start.
    """
    from collections import Counter

    counts = Counter(r["expected_severity_band"] for r in rows() if r["tier"] == "core")
    assert set(counts) == {"high_or_critical", "medium", "non_security_or_low"}, counts
    for band, n in counts.items():
        assert n >= 3, f"{band} has only {n} template(s); group-aware CV needs at least 3"


def test_every_scenario_has_a_manifest_and_no_manifest_is_orphaned():
    ids = {r["scenario_id"] for r in rows()}
    files = {p.stem for p in MANIFESTS.glob("*.yaml")}
    assert ids == files


def test_manifests_agree_with_the_catalogue():
    for row in rows():
        doc = yaml.safe_load((MANIFESTS / f"{row['scenario_id']}.yaml").read_text(encoding="utf-8"))
        assert doc["scenario_id"] == row["scenario_id"]
        assert doc["expected_policy_status"] == row["expected_policy_status"]
        assert str(doc["expected_drift"]).lower() == row["expected_drift"].lower()
        assert int(doc["planned_variations"]) == int(row["planned_variations"])


def test_scenario_ids_are_unique():
    ids = [r["scenario_id"] for r in rows()]
    assert len(ids) == len(set(ids))


def test_clean_controls_exist_and_expect_compliance():
    clean = [r for r in rows() if r["scenario_group"] == "clean_control"]
    assert clean, "a dataset with no clean negative control cannot measure false alerts"
    assert all(r["expected_policy_status"] == "compliant" for r in clean)


def test_every_severity_band_is_one_of_the_three_classes():
    allowed = {"non_security_or_low", "medium", "high_or_critical"}
    assert {r["expected_severity_band"] for r in rows()} <= allowed


def test_state_security_scenarios_need_no_aws():
    for row in rows():
        if row["scenario_group"] == "state_security":
            assert row["needs_aws"].lower() == "false"


def test_drift_manifests_agree_with_the_event_to_control_table():
    """S3-002 and DEL-001 named a control their own expected event does not map to.

    Nothing caught it until the first live run on 16 Oct scored two correct detections as
    misses. Workflow manifests are excluded: their controls come from the workflow scanner.
    """
    from terraguard.drift_normaliser import EVENT_TO_CONTROL

    mapping = {event.value: control for event, control in EVENT_TO_CONTROL.items()}
    for path in sorted(MANIFESTS.glob("*.yaml")):
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        if manifest.get("expected_evidence_source") != "terraform_plan_json":
            continue
        event = manifest.get("expected_normalised_event")
        if event in mapping:
            assert manifest.get("expected_control") == mapping[event], path.name


def test_run_log_masks_the_account_id():
    sys.path.insert(0, str(ROOT / "scenarios"))
    from _common import mask_account

    masked = mask_account("arn:aws:iam::123456789012:policy/p arn:aws:s3:::bucket")
    assert "123456789012" not in masked
    assert "arn:aws:iam::<account>:policy/p" in masked
    assert "arn:aws:s3:::bucket" in masked
