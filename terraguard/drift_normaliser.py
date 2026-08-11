"""Give a raw attribute diff its security meaning.

Terraform tells us *what* changed. It does not tell us whether that change matters. This
module is the deterministic bridge: one drift record in, zero or more normalised security
events out. Nothing here is learned - the models only rank events this module has already
established.
"""

from __future__ import annotations

from .models import (
    AttributeChange,
    ChangeAction,
    DriftRecord,
    EvidenceSource,
    Finding,
    NormalisedEvent,
)

__all__ = ["normalise_attribute", "normalise_record", "normalise", "NORMALISATION_TABLE"]

# path fragment -> (event when the change is a security regression, description)
_NETWORK_HINTS = ("cidr", "ipv4", "ipv6", "ip_range", "source_ranges")
_ENCRYPTION_HINTS = ("encrypt", "sse", "kms", "server_side_encryption")
_LOGGING_HINTS = ("logging", "log_file_validation", "enable_logging", "trail", "audit")
_PRIVILEGE_HINTS = ("action", "actions", "policy", "principal", "assume_role", "resource")
_OPERATIONAL_HINTS = ("tag", "tags", "description", "name")

NORMALISATION_TABLE = {
    NormalisedEvent.PUBLIC_NETWORK_ACCESS: "network reachable from any address",
    NormalisedEvent.PRIVILEGE_EXPANSION: "permission widened, wildcard or broader principal",
    NormalisedEvent.ENCRYPTION_DISABLED: "encryption turned off",
    NormalisedEvent.SECURITY_LOGGING_DISABLED: "security logging turned off",
    NormalisedEvent.OUT_OF_BAND_DELETION: "managed resource removed outside Terraform",
    NormalisedEvent.OPERATIONAL_DRIFT: "change with no security consequence",
}


def _matches(path: str, hints: tuple[str, ...]) -> bool:
    lowered = path.lower()
    return any(h in lowered for h in hints)


def normalise_attribute(change: AttributeChange) -> NormalisedEvent | None:
    """Classify a single attribute change.

    Direction matters. restricted -> public is a regression; public -> restricted is a
    repair and must not be reported as a security event, or the dataset fills with
    findings for changes that improved the posture.
    """
    before, after, path = change.before_category, change.after_category, change.path

    if _matches(path, _NETWORK_HINTS):
        if after == "public" and before != "public":
            return NormalisedEvent.PUBLIC_NETWORK_ACCESS
        return None

    if _matches(path, _ENCRYPTION_HINTS):
        if before == "enabled" and after in ("disabled", "absent"):
            return NormalisedEvent.ENCRYPTION_DISABLED
        return None

    if _matches(path, _LOGGING_HINTS):
        if before == "enabled" and after in ("disabled", "absent"):
            return NormalisedEvent.SECURITY_LOGGING_DISABLED
        return None

    if _matches(path, _PRIVILEGE_HINTS):
        if after == "wildcard" and before != "wildcard":
            return NormalisedEvent.PRIVILEGE_EXPANSION
        return None

    if change.sensitive or after == "sensitive":
        return NormalisedEvent.SENSITIVE_DATA_EXPOSURE

    if _matches(path, _OPERATIONAL_HINTS):
        return NormalisedEvent.OPERATIONAL_DRIFT

    return NormalisedEvent.OPERATIONAL_DRIFT


def normalise_record(record: DriftRecord, *, scenario_id: str | None = None) -> list[Finding]:
    """One drift record in, one finding per meaningful attribute change out."""
    findings: list[Finding] = []

    if record.change_action is ChangeAction.DELETE and record.is_remote_drift:
        findings.append(
            _finding(
                record,
                NormalisedEvent.OUT_OF_BAND_DELETION,
                attribute=None,
                scenario_id=scenario_id,
                detail=f"{record.resource_address} no longer exists in the provider",
            )
        )
        return findings

    for change in record.changed_attributes:
        event = normalise_attribute(change)
        if event is None:
            continue
        findings.append(
            _finding(
                record,
                event,
                attribute=change.path,
                scenario_id=scenario_id,
                detail=(f"{change.path}: {change.before_category} -> {change.after_category}"),
            )
        )
    return findings


def _finding(
    record: DriftRecord,
    event: NormalisedEvent,
    *,
    attribute: str | None,
    scenario_id: str | None,
    detail: str,
) -> Finding:
    suffix = attribute or record.change_action.value
    return Finding(
        finding_id=f"{record.resource_address}:{suffix}:{event.value}",
        scenario_id=scenario_id,
        evidence_source=EvidenceSource.TERRAFORM_PLAN_JSON,
        resource_type=record.resource_type,
        resource_address=record.resource_address,
        changed_attribute=attribute,
        normalised_event=event,
        detail=detail,
        explanation=NORMALISATION_TABLE.get(event, ""),
        raw={
            "is_remote_drift": record.is_remote_drift,
            "change_action": record.change_action.value,
        },
    )


def normalise(records: list[DriftRecord], *, scenario_id: str | None = None) -> list[Finding]:
    out: list[Finding] = []
    for record in records:
        out.extend(normalise_record(record, scenario_id=scenario_id))
    return out
