"""Redaction is the control that makes every other artefact safe to keep. Test it hardest."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from terraguard import redactor

FIXTURE = Path(__file__).parent / "fixtures" / "plan_sg_drift.json"
# Assembled rather than written literally: the pre-commit guard rejects any file that
# contains an AWS access key id, and it should stay that strict.
EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
MARKERS = ["TERRAGUARD_TEST_SECRET_002", "TERRAGUARD_TEST_SECRET_003", EXAMPLE_KEY]


@pytest.fixture()
def plan() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_sensitive_flagged_values_are_removed(plan):
    out = json.dumps(redactor.redact_plan_obj(plan))
    for marker in MARKERS:
        assert marker not in out, f"{marker} survived redaction"


def test_sensitivity_trees_are_stripped(plan):
    out = redactor.redact_plan_obj(plan)
    for change in out["resource_changes"]:
        assert "before_sensitive" not in change["change"]
        assert "after_sensitive" not in change["change"]


def test_non_sensitive_values_survive_for_analysis(plan):
    out = redactor.redact_plan_obj(plan)
    drift = out["resource_drift"][0]["change"]
    assert drift["after"]["cidr_ipv4"] == "0.0.0.0/0"
    assert drift["before"]["cidr_ipv4"] == "10.0.0.0/8"


def test_hash_is_stable_and_not_reversible():
    a = redactor.hash_value("TERRAGUARD_TEST_SECRET_001")
    b = redactor.hash_value("TERRAGUARD_TEST_SECRET_001")
    assert a == b
    assert "TERRAGUARD" not in a


def test_key_name_heuristic_catches_unflagged_secrets():
    node = {"client_secret": "not-marked-sensitive-by-provider"}
    out = redactor._redact(node, None, salt="")
    assert out["client_secret"].startswith(redactor.PLACEHOLDER)


def test_scrub_text_cleans_log_output():
    text = f"aws_access_key_id={EXAMPLE_KEY} marker=TERRAGUARD_TEST_SECRET_009"
    cleaned = redactor.scrub_text(text)
    assert "AKIA" not in cleaned
    assert "TERRAGUARD_TEST_SECRET_009" not in cleaned


def test_assert_clean_raises_on_leak():
    with pytest.raises(ValueError):
        redactor.assert_clean(f"password={EXAMPLE_KEY}")


def test_redact_plan_file_writes_clean_artefact(tmp_path):
    dst = tmp_path / "out.json"
    redactor.redact_plan_file(FIXTURE, dst)
    redactor.assert_clean(dst.read_text(encoding="utf-8"))
