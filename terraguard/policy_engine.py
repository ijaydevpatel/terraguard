"""Assess controls against collected evidence.

Four outcomes, and the fourth is the one that matters most:

* **compliant**      - the control applies, evidence was available, nothing was found
* **non_compliant**  - the control applies and a finding proves it was violated
* **not_applicable** - the control does not apply to this configuration at all
* **indeterminate**  - the control applies but the evidence needed was missing or unreadable

``indeterminate`` exists so that "we could not check" is never silently recorded as "it is
fine". Treating absent evidence as compliance is how a scanner produces false assurance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import EvidenceSource, Finding, PolicyStatus, Severity

__all__ = ["Control", "ControlAssessment", "load_controls", "assess", "assessment_coverage"]

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "non_security": Severity.NON_SECURITY,
}


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    tier: str
    description: str
    evidence_source: EvidenceSource
    applies_when: str
    decision: str
    expected_secure_result: str
    severity_if_violated: Severity
    remediation: str
    source: str
    # Resource-type prefixes this control governs. Empty means it applies to any target that
    # supplies the right evidence. `applies_when` is prose for a human; this is the machine
    # readable half, and without it the engine could never return not_applicable.
    applies_to: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Control:
        return cls(
            id=raw["id"],
            name=raw["name"],
            tier=raw.get("tier", "core"),
            description=(raw.get("description") or "").strip(),
            evidence_source=EvidenceSource(raw["evidence_source"]),
            applies_when=raw.get("applies_when", ""),
            applies_to=tuple(raw.get("applies_to") or ()),
            decision=raw.get("decision", ""),
            expected_secure_result=raw.get("expected_secure_result", ""),
            severity_if_violated=_SEVERITY.get(
                raw.get("severity_if_violated", "medium"), Severity.MEDIUM
            ),
            remediation=raw.get("remediation", ""),
            source=raw.get("source", ""),
        )


@dataclass
class ControlAssessment:
    control: Control
    status: PolicyStatus
    reason: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def control_id(self) -> str:
        return self.control.id


def load_controls(
    policy_dir: str | Path = "policies", *, include_optional: bool = False
) -> list[Control]:
    """Load the catalogue. Optional controls are excluded unless asked for."""
    controls: list[Control] = []
    for path in sorted(Path(policy_dir).glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in doc.get("controls") or []:
            control = Control.from_dict(raw)
            if control.tier == "optional" and not include_optional:
                continue
            controls.append(control)
    seen: set[str] = set()
    for c in controls:
        if c.id in seen:
            raise ValueError(f"duplicate control id {c.id}")
        seen.add(c.id)
    return sorted(controls, key=lambda c: c.id)


def assess(
    controls: list[Control],
    findings: list[Finding],
    *,
    available_evidence: set[EvidenceSource],
    observed_resource_types: set[str] | None = None,
) -> list[ControlAssessment]:
    """Evaluate every control against the findings and the evidence actually collected.

    `observed_resource_types` is what makes the fourth outcome real. Without it the engine
    could only say compliant, non-compliant or indeterminate, so a control about security
    group rules read as compliant on a plan containing no security groups at all. That is
    false assurance of exactly the kind `indeterminate` was introduced to prevent, arriving
    through a different door.

    It stays optional because a caller that genuinely does not know the inventory should not
    be forced to invent one; in that case the control is assessed as before.
    """
    by_control: dict[str, list[Finding]] = {}
    for f in findings:
        if f.control_id:
            by_control.setdefault(f.control_id, []).append(f)

    out: list[ControlAssessment] = []
    for control in controls:
        matched = by_control.get(control.id, [])
        if matched:
            if all(f.raw.get("indeterminate") for f in matched):
                out.append(
                    ControlAssessment(
                        control,
                        PolicyStatus.INDETERMINATE,
                        "evidence could not be read",
                        matched,
                    )
                )
            else:
                out.append(
                    ControlAssessment(
                        control,
                        PolicyStatus.NON_COMPLIANT,
                        matched[0].detail,
                        [f for f in matched if not f.raw.get("indeterminate")],
                    )
                )
            continue

        if (
            control.applies_to
            and observed_resource_types is not None
            and not any(
                observed.startswith(prefix)
                for prefix in control.applies_to
                for observed in observed_resource_types
            )
        ):
            out.append(
                ControlAssessment(
                    control,
                    PolicyStatus.NOT_APPLICABLE,
                    f"no {', '.join(control.applies_to)} resource in the target",
                )
            )
            continue

        if control.evidence_source not in available_evidence:
            out.append(
                ControlAssessment(
                    control,
                    PolicyStatus.INDETERMINATE,
                    f"no {control.evidence_source.value} evidence was collected",
                )
            )
            continue

        out.append(ControlAssessment(control, PolicyStatus.COMPLIANT, "no violation found"))
    return out


def assessment_coverage(assessments: list[ControlAssessment]) -> float:
    """Share of controls that reached a definite answer. Reported with every run."""
    if not assessments:
        return 0.0
    definite = sum(
        1 for a in assessments if a.status in (PolicyStatus.COMPLIANT, PolicyStatus.NON_COMPLIANT)
    )
    return definite / len(assessments)
