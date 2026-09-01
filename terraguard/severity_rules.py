"""The deterministic severity baseline - the non-AI comparator.

This is a direct transcription of `docs/SEVERITY_RUBRIC.md`. Every label carries the number
of the rule that produced it, so a disagreement can be about a rule rather than about an
impression.

It is frozen before any model is trained. If Logistic Regression and Random Forest cannot
beat a lookup table, that is a result worth reporting, and it can only be reported honestly
if the table was fixed first.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, NormalisedEvent, Severity

__all__ = ["SeverityBand", "Label", "classify", "classify_all", "RULES"]

# Three classes. Five needs more independent examples per class than the catalogue supplies.
HIGH_OR_CRITICAL = "high_or_critical"
MEDIUM = "medium"
NON_SECURITY_OR_LOW = "non_security_or_low"


@dataclass(frozen=True)
class Label:
    band: str
    rule: int
    reason: str

    @property
    def severity(self) -> Severity:
        return {
            HIGH_OR_CRITICAL: Severity.HIGH,
            MEDIUM: Severity.MEDIUM,
            NON_SECURITY_OR_LOW: Severity.LOW,
        }[self.band]


SeverityBand = str

RULES = {
    1: "exposes data or credentials directly",
    2: "grants access to someone who did not have it",
    3: "removes the ability to detect or recover",
    4: "weakens a defence that is not the last one",
    5: "no security consequence",
}

# Rule 3 splits on whether another control still covers the same ground. A trail is the only
# audit record; bucket access logging is not, while CloudTrail is running.
_SOLE_DETECTION_CONTROLS = {"TG-P05"}
_COVERED_DETECTION_EVENTS = {"s3_access_logging"}

# Rule 4: real weakening, but exploitation needs another failure first.
_SECONDARY_DEFENCE = {"TG-P04", "TG-P08"}


def classify(finding: Finding) -> Label:
    """Work down the ladder. Stop at the first rule that applies."""
    event = finding.normalised_event
    control = finding.control_id or ""
    detail = (finding.detail or "").lower()

    # Override: deletion outside Terraform, regardless of what was deleted. State and
    # reality have diverged and nothing says what else changed in the same session.
    if event is NormalisedEvent.OUT_OF_BAND_DELETION:
        return Label(
            HIGH_OR_CRITICAL, 1, "resource removed outside Terraform; state and reality diverge"
        )

    # Rule 1 - data or credentials exposed
    if event is NormalisedEvent.SENSITIVE_DATA_EXPOSURE:
        return Label(HIGH_OR_CRITICAL, 1, "credential or sensitive value exposed")
    if control in ("TG-P01", "TG-P07"):
        return Label(HIGH_OR_CRITICAL, 1, "state or plan artefact carries every resource attribute")
    if event is NormalisedEvent.ENCRYPTION_DISABLED:
        return Label(HIGH_OR_CRITICAL, 1, "data left unencrypted at rest")

    # Rule 2 - access granted to someone who did not have it
    if event is NormalisedEvent.PUBLIC_NETWORK_ACCESS:
        return Label(HIGH_OR_CRITICAL, 2, "reachable from any address")
    if event is NormalisedEvent.PRIVILEGE_EXPANSION and control not in _SECONDARY_DEFENCE:
        return Label(HIGH_OR_CRITICAL, 2, "permission widened beyond what was granted")
    if control == "TG-P02":
        return Label(HIGH_OR_CRITICAL, 2, "state reachable without the intended access control")

    # Rule 3 - detection or recovery removed; sole control or not
    if event is NormalisedEvent.SECURITY_LOGGING_DISABLED:
        if any(h in detail for h in _COVERED_DETECTION_EVENTS):
            return Label(
                MEDIUM, 3, "logging removed but another control still records the activity"
            )
        return Label(HIGH_OR_CRITICAL, 3, "the only record of activity was removed")
    if control in _SOLE_DETECTION_CONTROLS:
        return Label(MEDIUM, 3, "recovery weakened; the state itself is still protected")
    if control == "TG-P03":
        return Label(HIGH_OR_CRITICAL, 1, "state stored without encryption at rest")

    # Rule 4 - a defence weakened, but not the last one
    if control in _SECONDARY_DEFENCE:
        return Label(MEDIUM, 4, "defence weakened; exploitation needs a second failure")

    # Rule 5
    if event is NormalisedEvent.OPERATIONAL_DRIFT:
        return Label(NON_SECURITY_OR_LOW, 5, "configuration changed, security position did not")

    return Label(NON_SECURITY_OR_LOW, 5, "no rule matched a security consequence")


def classify_all(findings: list[Finding]) -> list[Label]:
    return [classify(f) for f in findings]
