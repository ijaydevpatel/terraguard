"""Read Terraform's machine-readable plan.

Two collections matter and they mean different things:

* ``resource_drift``   - what Terraform found in the provider that does not match prior
                         state. This is drift: someone changed the infrastructure outside
                         Terraform.
* ``resource_changes`` - what Terraform intends to do to reconcile configuration with
                         state. This is an intentional source change, not drift.

Conflating the two would invalidate every severity label downstream, so the distinction is
carried explicitly on every record as ``is_remote_drift``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ChangeAction, DriftRecord

__all__ = ["parse_plan", "parse_plan_file", "classify_action", "PlanParseError"]


class PlanParseError(ValueError):
    """The document is not a Terraform plan we can read."""


def classify_action(actions: list[str] | None) -> ChangeAction:
    """Map Terraform's ``change.actions`` array onto a single action.

    Terraform expresses replacement as an ordered pair - ``["delete", "create"]`` or
    ``["create", "delete"]`` depending on ``create_before_destroy`` - so a replacement must
    be recognised from the pair, never from the first element alone.
    """
    if not actions:
        return ChangeAction.NO_OP
    normalised = [a.lower() for a in actions]
    if set(normalised) == {"create", "delete"}:
        return ChangeAction.REPLACE
    first = normalised[0]
    try:
        return ChangeAction(first)
    except ValueError:
        return ChangeAction.NO_OP


def _record(item: dict[str, Any], *, remote: bool) -> DriftRecord | None:
    change = item.get("change") or {}
    action = classify_action(change.get("actions"))
    if action is ChangeAction.NO_OP or action is ChangeAction.READ:
        return None
    address = item.get("address")
    if not address:
        return None
    return DriftRecord(
        resource_address=address,
        resource_type=item.get("type") or address.split(".")[0],
        provider_name=item.get("provider_name"),
        change_action=action,
        is_remote_drift=remote,
    )


def parse_plan(plan: dict[str, Any]) -> list[DriftRecord]:
    """Return one record per meaningful change in the plan document.

    No-ops and data reads are dropped: they are not findings and would only dilute the
    dataset.
    """
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise PlanParseError("not a Terraform plan JSON document (no format_version)")

    records: list[DriftRecord] = []
    for item in plan.get("resource_drift") or []:
        rec = _record(item, remote=True)
        if rec is not None:
            records.append(rec)
    for item in plan.get("resource_changes") or []:
        rec = _record(item, remote=False)
        if rec is not None:
            records.append(rec)
    return records


def raw_changes(plan: dict[str, Any]) -> list[tuple[dict[str, Any], bool]]:
    """Yield ``(item, is_remote_drift)`` pairs so the extractor can diff before/after."""
    pairs: list[tuple[dict[str, Any], bool]] = []
    for item in plan.get("resource_drift") or []:
        pairs.append((item, True))
    for item in plan.get("resource_changes") or []:
        pairs.append((item, False))
    return pairs


def parse_plan_file(path: str | Path) -> list[DriftRecord]:
    return parse_plan(json.loads(Path(path).read_text(encoding="utf-8")))
