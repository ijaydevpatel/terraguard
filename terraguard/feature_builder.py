"""Turn findings into model features, without handing the model the answer.

The severity labels come from `severity_rules.py`, which is a deterministic function of
`control_id` and `normalised_event`. If those two fields are also fed in as features, the
model recovers the lookup table exactly and scores near-perfectly while learning nothing.
That is leakage, not a result.

So the sixteen features below are all *context*: where the evidence came from, what kind of
resource it touches, what the attribute path looks like, what else happened in the same run.
The two rule inputs are built separately by `build_leaky_matrix`, which exists only so the
leakage can be measured and reported rather than asserted.

Nothing here reads a severity label. `build_matrix` returns X; labels are attached by the
caller from `severity_rules.classify`.
"""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "FEATURE_NAMES",
    "RULE_INPUT_NAMES",
    "FindingRow",
    "load_rows",
    "build_matrix",
    "build_leaky_matrix",
    "groups_for",
]

# The sixteen context features. Order is fixed: it is the column order of the matrix and
# the order coefficients and importances are reported in.
FEATURE_NAMES = [
    "evidence_source",
    "resource_type",
    "attribute_depth",
    "is_remote_drift",
    "sensitive_data_involved",
    "findings_in_run",
    "assessment_coverage",
    "run_policy_status",
    "path_mentions_public",
    "path_mentions_encryption",
    "path_mentions_logging",
    "path_mentions_permission",
    "detail_length",
    "in_history_only",
    "is_state_artefact",
    "persistence_across_runs",
]

# Withheld by default. These are what the rule ladder switches on.
RULE_INPUT_NAMES = ["control_id", "normalised_event"]

CATEGORICAL = {"evidence_source", "resource_type", "run_policy_status"}

_PUBLIC_HINTS = ("public", "cidr", "0.0.0.0", "::/0", "ingress", "acl")
_ENCRYPTION_HINTS = ("encrypt", "kms", "sse", "tls")
_LOGGING_HINTS = ("log", "trail", "audit", "versioning")
_PERMISSION_HINTS = ("permission", "policy", "role", "action", "principal", "token", "scope")
_STATE_ARTEFACT_HINTS = (".tfstate", "tfplan", "plan.json", ".terraform", "crash.log")


@dataclass(frozen=True)
class FindingRow:
    """One finding joined to the run it came from."""

    run_id: str
    scenario_id: str
    finding_id: str
    evidence_source: str
    control_id: str
    normalised_event: str
    resource_address: str
    detail: str
    resource_type: str = ""
    is_remote_drift: bool = False
    in_history_only: bool = False
    findings_in_run: int = 0
    assessment_coverage: float = 0.0
    run_policy_status: str = ""
    persistence_across_runs: int = 0


def _truthy(value: str | None) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def _float(value: str | None) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def load_rows(findings_csv: str | Path, observations_csv: str | Path) -> list[FindingRow]:
    """Join findings to their run, and count how often each finding id recurs.

    `persistence_across_runs` is the point of the join: a finding that appears in every
    replay of a scenario is a stable property of the configuration, while one that appears
    once is closer to noise. The redactor preserves the shape of sensitive values precisely
    so that this count can be made without the value being recoverable.
    """
    runs: dict[str, dict[str, str]] = {}
    with open(observations_csv, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            runs[row["run_id"]] = row

    with open(findings_csv, encoding="utf-8", newline="") as fh:
        raw = list(csv.DictReader(fh))

    per_run = Counter(r["run_id"] for r in raw)
    recurrence = Counter(r["finding_id"] for r in raw)

    rows: list[FindingRow] = []
    for r in raw:
        run = runs.get(r["run_id"], {})
        address = r.get("resource_address") or ""
        rows.append(
            FindingRow(
                run_id=r["run_id"],
                scenario_id=r["scenario_id"],
                finding_id=r["finding_id"],
                evidence_source=r.get("evidence_source") or "",
                control_id=r.get("control_id") or "",
                normalised_event=r.get("normalised_event") or "",
                resource_address=address,
                detail=r.get("detail") or "",
                resource_type=r.get("resource_type") or _infer_resource_type(address),
                is_remote_drift=_truthy(r.get("is_remote_drift")),
                in_history_only="history" in (r.get("detail") or "").lower(),
                findings_in_run=per_run[r["run_id"]],
                assessment_coverage=_float(run.get("assessment_coverage")),
                run_policy_status=run.get("policy_status") or "",
                persistence_across_runs=recurrence[r["finding_id"]],
            )
        )
    return rows


def _infer_resource_type(address: str) -> str:
    """Terraform addresses are `type.name`; repository findings are just paths."""
    if not address:
        return "unknown"
    head = address.split(".")[0]
    if head.startswith("aws_") or head.startswith("github_"):
        return head
    return "repository_file"


def _any_hint(text: str, hints: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(h in lowered for h in hints)


def _row_features(row: FindingRow) -> dict[str, object]:
    path = f"{row.resource_address} {row.detail}"
    return {
        "evidence_source": row.evidence_source or "unknown",
        "resource_type": row.resource_type or "unknown",
        # Depth stands in for how specific the finding is: `tags.Owner` is a leaf,
        # a bare resource address is the whole object.
        "attribute_depth": row.resource_address.count(".") + row.resource_address.count("/"),
        "is_remote_drift": int(row.is_remote_drift),
        "sensitive_data_involved": int("[REDACTED]" in row.detail),
        "findings_in_run": row.findings_in_run,
        "assessment_coverage": row.assessment_coverage,
        "run_policy_status": row.run_policy_status or "unknown",
        "path_mentions_public": int(_any_hint(path, _PUBLIC_HINTS)),
        "path_mentions_encryption": int(_any_hint(path, _ENCRYPTION_HINTS)),
        "path_mentions_logging": int(_any_hint(path, _LOGGING_HINTS)),
        "path_mentions_permission": int(_any_hint(path, _PERMISSION_HINTS)),
        "detail_length": len(row.detail),
        "in_history_only": int(row.in_history_only),
        "is_state_artefact": int(_any_hint(row.resource_address, _STATE_ARTEFACT_HINTS)),
        "persistence_across_runs": row.persistence_across_runs,
    }


def build_matrix(rows: list[FindingRow]) -> tuple[list[dict[str, object]], list[str]]:
    """Context features only. Returns (records, feature_names) for a DictVectorizer."""
    return [_row_features(r) for r in rows], list(FEATURE_NAMES)


def build_leaky_matrix(rows: list[FindingRow]) -> tuple[list[dict[str, object]], list[str]]:
    """Context features plus the two fields the severity ladder switches on.

    Only for the leakage demonstration in T076. A model trained on this should score close
    to perfect, and that number belongs in the write-up as evidence of what withholding the
    rule inputs is protecting against - not in the results table as a model score.
    """
    records = []
    for row, base in zip(rows, (_row_features(r) for r in rows), strict=True):
        enriched = dict(base)
        enriched["control_id"] = row.control_id or "none"
        enriched["normalised_event"] = row.normalised_event or "none"
        records.append(enriched)
    return records, list(FEATURE_NAMES) + list(RULE_INPUT_NAMES)


def groups_for(rows: list[FindingRow]) -> list[str]:
    """Group key for StratifiedGroupKFold: the scenario template.

    Variations of one template are near-duplicates of each other, so grouping by template
    is what stops the model being scored on near-copies of its own training data.
    """
    return [r.scenario_id for r in rows]
