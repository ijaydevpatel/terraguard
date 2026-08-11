"""Phase 2: attribute paths and value categories."""

from __future__ import annotations

import json
from pathlib import Path

from terraguard.drift_extractor import categorise, extract_changes, extract_from_plan, flatten

FIXTURE = Path(__file__).parent / "fixtures" / "plan_sg_drift.json"


def test_lists_are_indexed_so_rules_do_not_collapse():
    flat = flatten({"ingress": [{"cidr": "10.0.0.0/8"}, {"cidr": "0.0.0.0/0"}]})
    assert flat["ingress.0.cidr"] == "10.0.0.0/8"
    assert flat["ingress.1.cidr"] == "0.0.0.0/0"


def test_open_cidr_is_public_in_both_address_families():
    assert categorise("cidr_ipv4", "0.0.0.0/0") == "public"
    assert categorise("cidr_ipv6", "::/0") == "public"
    assert categorise("cidr_ipv4", "10.0.0.0/8") == "restricted"


def test_booleans_and_wildcards():
    assert categorise("encrypted", True) == "enabled"
    assert categorise("encrypted", False) == "disabled"
    assert categorise("Action", "*") == "wildcard"
    assert categorise("versioning", "Suspended") == "disabled"


def test_only_real_differences_are_reported():
    changes = extract_changes({"a": 1, "b": 2}, {"a": 1, "b": 3})
    assert [c.path for c in changes] == ["b"]


def test_end_to_end_extraction_finds_the_open_cidr():
    plan = json.loads(FIXTURE.read_text(encoding="utf-8"))
    records = extract_from_plan(plan)
    sg = next(r for r in records if "security_group" in r.resource_type)
    paths = {c.path: c for c in sg.changed_attributes}
    assert paths["cidr_ipv4"].before_category == "restricted"
    assert paths["cidr_ipv4"].after_category == "public"


def test_sensitive_values_are_redacted_in_the_diff():
    plan = json.loads(FIXTURE.read_text(encoding="utf-8"))
    records = extract_from_plan(plan)
    for rec in records:
        for change in rec.changed_attributes:
            for text in (change.before_redacted, change.after_redacted):
                assert text is None or "TERRAGUARD_TEST_SECRET" not in text
