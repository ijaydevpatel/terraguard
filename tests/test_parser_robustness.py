"""T033: the parser must survive documents it was not designed for.

The original plan was to run 30 to 50 TerraDS or TerraGoat samples through it. Those are
external corpora this project does not ship, so this suite does the part that can be done
honestly: a generated set of malformed, truncated, unusual and hostile plan documents, each
asserting that the parser either extracts something sensible or refuses, and never raises.

A scanner that crashes on an odd document fails open in practice, because the pipeline step
that was meant to inspect it simply does not run.
"""

from __future__ import annotations

import json

import pytest

from terraguard.drift_extractor import extract_from_plan
from terraguard.drift_normaliser import normalise

BASE = {
    "format_version": "1.2",
    "terraform_version": "1.11.0",
    "resource_drift": [
        {
            "address": "aws_s3_bucket.b",
            "type": "aws_s3_bucket",
            "name": "b",
            "change": {
                "actions": ["update"],
                "before": {"tags": {"a": "1"}},
                "after": {"tags": {"a": "2"}},
                "before_sensitive": {},
                "after_sensitive": {},
            },
        }
    ],
}


def _mutate(**overrides) -> dict:
    doc = json.loads(json.dumps(BASE))
    doc.update(overrides)
    return doc


MALFORMED: list[tuple[str, dict]] = [
    ("empty document", {}),
    ("no format_version", _mutate(format_version=None)),
    ("drift is not a list", _mutate(resource_drift={"a": 1})),
    ("drift entries are strings", _mutate(resource_drift=["nope"])),
    ("change missing", _mutate(resource_drift=[{"address": "a.b", "type": "a"}])),
    ("change is null", _mutate(resource_drift=[{"address": "a.b", "change": None}])),
    ("actions missing", _mutate(resource_drift=[{"address": "a.b", "change": {"after": {}}}])),
    (
        "actions not a list",
        _mutate(resource_drift=[{"address": "a.b", "change": {"actions": "update"}}]),
    ),
    (
        "before and after both null",
        _mutate(
            resource_drift=[
                {"address": "a.b", "change": {"actions": ["update"], "before": None, "after": None}}
            ]
        ),
    ),
    (
        "sensitivity tree is the wrong shape",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["update"],
                        "before": {"x": 1},
                        "after": {"x": 2},
                        "after_sensitive": [True, False],
                    },
                }
            ]
        ),
    ),
    (
        "sensitivity list shorter than values",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["update"],
                        "before": {"l": [1, 2, 3]},
                        "after": {"l": [4, 5, 6]},
                        "after_sensitive": {"l": [True]},
                    },
                }
            ]
        ),
    ),
    (
        "deeply nested attributes",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["update"],
                        "before": {"a": {"b": {"c": {"d": {"e": "1"}}}}},
                        "after": {"a": {"b": {"c": {"d": {"e": "2"}}}}},
                    },
                }
            ]
        ),
    ),
    (
        "unicode and control characters",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["update"],
                        "before": {"n": "café\u0000"},
                        "after": {"n": "café‮"},
                    },
                }
            ]
        ),
    ),
    (
        "very long value",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["update"],
                        "before": {"n": "x" * 50_000},
                        "after": {"n": "y" * 50_000},
                    },
                }
            ]
        ),
    ),
    (
        "numeric keys",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {"actions": ["update"], "before": {"1": "a"}, "after": {"1": "b"}},
                }
            ]
        ),
    ),
    (
        "list of lists",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["update"],
                        "before": {"l": [[1], [2]]},
                        "after": {"l": [[3], [4]]},
                    },
                }
            ]
        ),
    ),
    (
        "unknown action verb",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {"actions": ["teleport"], "before": {"x": 1}, "after": {"x": 2}},
                }
            ]
        ),
    ),
    (
        "create and delete pair",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {
                        "actions": ["create", "delete"],
                        "before": {"x": 1},
                        "after": {"x": 2},
                    },
                }
            ]
        ),
    ),
    (
        "no-op is dropped",
        _mutate(
            resource_drift=[
                {
                    "address": "a.b",
                    "type": "t",
                    "change": {"actions": ["no-op"], "before": {"x": 1}, "after": {"x": 1}},
                }
            ]
        ),
    ),
    (
        "data source read",
        _mutate(
            resource_drift=[
                {
                    "address": "data.a.b",
                    "mode": "data",
                    "type": "t",
                    "change": {"actions": ["read"], "before": None, "after": {"x": 1}},
                }
            ]
        ),
    ),
    (
        "resource_changes instead of drift",
        {"format_version": "1.2", "resource_changes": BASE["resource_drift"]},
    ),
    (
        "both collections present",
        {
            "format_version": "1.2",
            "resource_drift": BASE["resource_drift"],
            "resource_changes": BASE["resource_drift"],
        },
    ),
]


@pytest.mark.parametrize("name,doc", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_parser_never_raises_on_an_odd_document(name, doc):
    """Refusing is acceptable. Crashing is not: the step that should inspect it stops running."""
    records = extract_from_plan(doc)
    assert isinstance(records, list)
    findings = normalise(records, scenario_id="robustness")
    assert isinstance(findings, list)


@pytest.mark.parametrize("name,doc", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_every_finding_from_an_odd_document_is_still_well_formed(name, doc):
    for finding in normalise(extract_from_plan(doc), scenario_id="robustness"):
        assert finding.finding_id
        assert finding.evidence_source is not None


def test_a_no_op_produces_nothing():
    doc = _mutate(
        resource_drift=[
            {
                "address": "a.b",
                "type": "t",
                "change": {"actions": ["no-op"], "before": {"x": 1}, "after": {"x": 1}},
            }
        ]
    )
    assert normalise(extract_from_plan(doc), scenario_id="r") == []
