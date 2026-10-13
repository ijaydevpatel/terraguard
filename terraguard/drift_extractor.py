"""Turn a before/after pair into changed attribute paths with categorised values.

The category is what the feature builder and the normaliser actually use. Raw values are
kept only in redacted form, because a plan can carry secrets and this output is written to
disk.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .models import AttributeChange, ChangeAction, DriftRecord
from .plan_parser import classify_action
from .redactor import redact_scalar, value_looks_sensitive

__all__ = ["flatten", "categorise", "extract_changes", "extract_from_plan"]

_OPEN_V4 = "0.0.0.0/0"
_OPEN_V6 = "::/0"


def flatten(node: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts and lists into dotted paths.

    Lists are indexed rather than ignored, because ``ingress.0.cidr_blocks`` and
    ``ingress.1.cidr_blocks`` are different rules and must not collapse into one path.
    """
    flat: dict[str, Any] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            flat.update(flatten(value, f"{prefix}.{key}" if prefix else key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            flat.update(flatten(value, f"{prefix}.{index}" if prefix else str(index)))
    else:
        flat[prefix] = node
    return flat


def _is_open_cidr(value: str) -> bool:
    if value in (_OPEN_V4, _OPEN_V6):
        return True
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return net.prefixlen == 0


_POLICY_WILDCARD = re.compile(
    r'"(?:Action|Resource|Principal)"\s*:\s*(?:"\*"|\[[^]]*"\*"[^]]*\])', re.IGNORECASE
)


def categorise(path: str, value: Any) -> str:
    """Reduce a value to a small vocabulary the rest of the pipeline can reason about."""
    if value is None:
        return "absent"
    lowered = path.lower()
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    if isinstance(value, str):
        if "cidr" in lowered or lowered.endswith(("_ip", "ip_range")):
            return "public" if _is_open_cidr(value) else "restricted"
        # An encryption or logging attribute emptied is that control removed, not a value
        # change. Without this, turning encryption off read as value -> value and the
        # normaliser saw nothing worth reporting.
        if not value.strip():
            return "absent"
        if value == "*":
            return "wildcard"
        if lowered.endswith(("action", "actions", "resource", "resources")) and value.endswith("*"):
            return "wildcard"
        # IAM policies arrive as a JSON string, so the wildcard is inside the document
        # rather than being the whole value.
        if _POLICY_WILDCARD.search(value):
            return "wildcard"
        if value.lower() in ("enabled", "true", "on"):
            return "enabled"
        if value.lower() in ("disabled", "false", "off", "suspended"):
            return "disabled"
        if value_looks_sensitive(value):
            return "sensitive"
        return "value"
    if isinstance(value, int | float):
        return "numeric"
    return "value"


def extract_changes(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    *,
    salt: str = "",
) -> list[AttributeChange]:
    """Diff two attribute trees and describe only what actually changed."""
    flat_before = flatten(before or {})
    flat_after = flatten(after or {})
    changes: list[AttributeChange] = []
    for path in sorted(set(flat_before) | set(flat_after)):
        old = flat_before.get(path)
        new = flat_after.get(path)
        if old == new:
            continue
        sensitive = value_looks_sensitive(old) or value_looks_sensitive(new)
        changes.append(
            AttributeChange(
                path=path,
                before_category=categorise(path, old),
                after_category=categorise(path, new),
                before_redacted=redact_scalar(old, salt=salt) if sensitive else _short(old),
                after_redacted=redact_scalar(new, salt=salt) if sensitive else _short(new),
                sensitive=sensitive,
            )
        )
    return changes


def _short(value: Any, limit: int = 120) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def extract_from_plan(plan: dict[str, Any], *, salt: str = "") -> list[DriftRecord]:
    """Full pass: plan document in, populated DriftRecords out."""
    from .plan_parser import raw_changes

    records: list[DriftRecord] = []
    for item, remote in raw_changes(plan):
        change = item.get("change") or {}
        action = classify_action(change.get("actions"))
        if action in (ChangeAction.NO_OP, ChangeAction.READ):
            continue
        address = item.get("address")
        if not address:
            continue
        records.append(
            DriftRecord(
                resource_address=address,
                resource_type=item.get("type") or address.split(".")[0],
                provider_name=item.get("provider_name"),
                change_action=action,
                is_remote_drift=remote,
                changed_attributes=extract_changes(
                    change.get("before"), change.get("after"), salt=salt
                ),
            )
        )
    return records
