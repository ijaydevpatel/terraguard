"""Redaction. Runs on write, never on read.

Anything leaving a temp directory passes through here first. Terraform plan JSON
marks sensitive values in parallel `before_sensitive` / `after_sensitive` trees;
we honour those, and additionally apply key-name and value-shape heuristics
because provider coverage of the sensitive flag is inconsistent.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

PLACEHOLDER = "[REDACTED]"

SENSITIVE_KEY_RE = re.compile(
    r"(secret|password|passwd|token|private_key|access_key|secret_key|credential"
    r"|session_token|client_secret|api_key|certificate|kms_key_id|connection_string)",
    re.IGNORECASE,
)

VALUE_PATTERNS = [
    re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),          # AWS key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),                          # PEM
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                                  # GitHub token
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"TERRAGUARD_TEST_SECRET_\d+"),                                  # synthetic marker
]


def hash_value(value: Any, salt: str = "") -> str:
    """Stable, non-reversible reference so the same value can be correlated across runs."""
    digest = hashlib.sha256((salt + repr(value)).encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


def value_looks_sensitive(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return any(p.search(value) for p in VALUE_PATTERNS)


def redact_scalar(value: Any, *, keep_shape: bool = True, salt: str = "") -> Any:
    """Replace a value while preserving enough shape to stay analysable."""
    if value is None or isinstance(value, bool):
        return value
    if not keep_shape:
        return PLACEHOLDER
    if isinstance(value, str):
        return f"{PLACEHOLDER}:len={len(value)}:{hash_value(value, salt)}"
    return f"{PLACEHOLDER}:{hash_value(value, salt)}"


def scrub_text(text: str) -> str:
    """Strip secret-shaped substrings out of free text such as captured log output."""
    for pattern in VALUE_PATTERNS:
        text = pattern.sub(PLACEHOLDER, text)
    return text


def _redact(node: Any, sensitive: Any, *, salt: str, key: str | None = None) -> Any:
    """Walk a plan-JSON value tree alongside its parallel sensitivity tree."""
    if sensitive is True:
        return redact_scalar(node, salt=salt)

    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for k, v in node.items():
            sub = sensitive.get(k) if isinstance(sensitive, dict) else None
            if SENSITIVE_KEY_RE.search(k) and not isinstance(v, (dict, list)):
                out[k] = redact_scalar(v, salt=salt)
            else:
                out[k] = _redact(v, sub, salt=salt, key=k)
        return out

    if isinstance(node, list):
        subs = sensitive if isinstance(sensitive, list) else [None] * len(node)
        if len(subs) != len(node):
            subs = [None] * len(node)
        return [_redact(v, s, salt=salt, key=key) for v, s in zip(node, subs)]

    if value_looks_sensitive(node):
        return redact_scalar(node, salt=salt)
    return node


def redact_plan_obj(plan: dict[str, Any], *, salt: str = "") -> dict[str, Any]:
    """Return a sanitised copy of a parsed Terraform plan JSON document."""
    out = json.loads(json.dumps(plan))  # cheap deep copy; plans are small here

    for collection in ("resource_changes", "resource_drift"):
        for item in out.get(collection, []) or []:
            change = item.get("change") or {}
            for side in ("before", "after"):
                if side in change:
                    change[side] = _redact(
                        change[side], change.get(f"{side}_sensitive"), salt=salt
                    )
            change.pop("before_sensitive", None)
            change.pop("after_sensitive", None)
            change.pop("after_unknown", None)

    for key in ("prior_state", "planned_values", "variables", "outputs", "configuration"):
        if key in out:
            out[key] = _redact(out[key], None, salt=salt)

    out.setdefault("terraguard", {})["redacted"] = True
    return out


def redact_plan_file(src: str | Path, dst: str | Path, *, salt: str = "") -> Path:
    """Read plan JSON, sanitise it, write it out. The destination is the only safe artefact."""
    src, dst = Path(src), Path(dst)
    plan = json.loads(src.read_text(encoding="utf-8"))
    sanitised = redact_plan_obj(plan, salt=salt)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(sanitised, indent=2), encoding="utf-8")
    return dst


def assert_clean(text: str) -> None:
    """Raise if any known secret shape survived. Used as a last gate before output."""
    for pattern in VALUE_PATTERNS:
        match = pattern.search(text)
        if match and not match.group(0).startswith(PLACEHOLDER):
            raise ValueError(f"redaction failed: {pattern.pattern} still present")
