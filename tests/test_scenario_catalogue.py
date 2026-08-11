"""Phase 5: the catalogue and its manifests must agree, before any run happens."""

from __future__ import annotations

import csv
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "datasets" / "scenario_catalogue.csv"
MANIFESTS = ROOT / "datasets" / "scenario_manifests"


def rows() -> list[dict]:
    with CATALOGUE.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_catalogue_has_ten_to_twelve_core_templates():
    core = [r for r in rows() if r["tier"] == "core"]
    assert 10 <= len(core) <= 12


def test_planned_core_observations_are_in_the_sixty_to_hundred_band():
    core = sum(int(r["planned_variations"]) for r in rows() if r["tier"] == "core")
    assert 60 <= core <= 100, core


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
