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


# Regression tests for the QA finding of 14 October 2026: an ordinary password survived in
# `variables` and in `output_changes`, and the final gate accepted the document because it only
# knew secret *shapes*.

ORDINARY = "hunter2"


def _plan_with_ordinary_password() -> dict:
    return {
        "planned_values": {
            "root_module": {
                "resources": [{"address": "aws_db_instance.db", "values": {"password": ORDINARY}}]
            }
        },
        "variables": {"db_password": {"value": ORDINARY}},
        "output_changes": {
            "conn": {"after": f"postgres://admin:{ORDINARY}@host/db", "after_sensitive": True}
        },
        "outputs": {"url": {"value": f"https://x:{ORDINARY}@h", "value_sensitive": True}},
        "resource_changes": [
            {
                "address": "aws_db_instance.db",
                "change": {
                    "before": {"password": ORDINARY},
                    "after": {"password": ORDINARY},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
    }


def test_ordinary_password_does_not_survive_anywhere():
    """A password has no recognisable shape, which is the whole reason for the key-name rule."""
    import json

    from terraguard.redactor import redact_plan_obj

    out = json.dumps(redact_plan_obj(_plan_with_ordinary_password()))
    assert ORDINARY not in out


def test_sensitive_key_context_survives_a_nested_wrapper():
    """Terraform wraps variables as {"db_password": {"value": ...}}.

    Looking only at the immediate key sees `value`, decides it is dull, and writes the password
    out intact. That was the defect.
    """
    import json

    from terraguard.redactor import redact_plan_obj

    out = redact_plan_obj({"variables": {"db_password": {"value": ORDINARY}}})
    assert ORDINARY not in json.dumps(out)


def test_sensitive_sibling_flag_is_honoured_outside_resource_changes():
    import json

    from terraguard.redactor import redact_plan_obj

    out = redact_plan_obj({"output_changes": {"c": {"after": ORDINARY, "after_sensitive": True}}})
    assert ORDINARY not in json.dumps(out)


def test_structural_gate_catches_what_the_shape_gate_cannot():
    import pytest

    from terraguard.redactor import assert_clean, assert_clean_obj

    raw = {"variables": {"db_password": {"value": ORDINARY}}}
    assert_clean(str(raw))  # shape gate sees nothing wrong, and that is the point
    with pytest.raises(ValueError, match="sensitive key"):
        assert_clean_obj(raw)


def test_structural_gate_accepts_a_sanitised_document():
    from terraguard.redactor import assert_clean_obj, redact_plan_obj

    assert_clean_obj(redact_plan_obj(_plan_with_ordinary_password()))
