"""Phase 2: the parser must tell drift apart from intentional change."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from terraguard.models import ChangeAction
from terraguard.plan_parser import PlanParseError, classify_action, parse_plan, parse_plan_file

FIXTURE = Path(__file__).parent / "fixtures" / "plan_sg_drift.json"


@pytest.fixture()
def plan() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_replacement_is_recognised_from_the_pair_not_the_first_element():
    assert classify_action(["delete", "create"]) is ChangeAction.REPLACE
    assert classify_action(["create", "delete"]) is ChangeAction.REPLACE
    assert classify_action(["delete"]) is ChangeAction.DELETE
    assert classify_action(["update"]) is ChangeAction.UPDATE
    assert classify_action([]) is ChangeAction.NO_OP
    assert classify_action(None) is ChangeAction.NO_OP


def test_unknown_action_does_not_raise():
    assert classify_action(["forget"]) is ChangeAction.NO_OP


def test_drift_and_planned_change_are_distinguished(plan):
    records = parse_plan(plan)
    drift = [r for r in records if r.is_remote_drift]
    planned = [r for r in records if not r.is_remote_drift]
    assert len(drift) == 2, "two entries in resource_drift"
    assert len(planned) == 1, "one entry in resource_changes"
    assert all(r.resource_address for r in records)


def test_no_ops_are_dropped():
    doc = {
        "format_version": "1.2",
        "resource_drift": [
            {
                "address": "aws_s3_bucket.a",
                "type": "aws_s3_bucket",
                "change": {"actions": ["no-op"]},
            }
        ],
    }
    assert parse_plan(doc) == []


def test_non_plan_document_is_rejected():
    with pytest.raises(PlanParseError):
        parse_plan({"hello": "world"})


def test_parse_from_file(tmp_path):
    assert len(parse_plan_file(FIXTURE)) == 3
