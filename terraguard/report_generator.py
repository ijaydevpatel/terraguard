"""Turn findings into a report a person can act on, with nothing sensitive in it.

Two output shapes, one record type. The terminal view is for someone reading a CI log; the
JSON view is for a machine and for the appendix of the write-up.

The redaction gate runs on the finished report, not on the inputs. Everything upstream has
already redacted, but a report is the artefact that actually leaves the machine - it gets
pasted into tickets, uploaded as a CI artefact and quoted in the dissertation. A second check
at the boundary costs nothing and is the one that matters.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .feature_builder import FindingRow
from .model_predictor import LOW_CONFIDENCE, Prediction, SeverityPredictor
from .severity_rules import HIGH_OR_CRITICAL, MEDIUM, NON_SECURITY_OR_LOW

__all__ = [
    "ReportRecord",
    "REPORT_FIELDS",
    "build_report",
    "render_terminal",
    "render_json",
    "render_csv",
]

REPORT_FIELDS = [
    "run_id",
    "scenario_id",
    "finding_id",
    "evidence_source",
    "control_id",
    "resource_type",
    "resource_address",
    "normalised_event",
    "detail",
    "run_policy_status",
    "assessment_coverage",
    "severity_band",
    "severity_rule",
    "severity_reason",
    "model_band",
    "model_confidence",
    "model_agrees",
]

_ORDER = {HIGH_OR_CRITICAL: 0, MEDIUM: 1, NON_SECURITY_OR_LOW: 2}

# Anything that looks like a live credential must never reach a report. The redactor replaces
# values with a shape-preserving marker, so the marker is expected; a raw key is not.
_FORBIDDEN = ("AKIA", "ASIA", "-----BEGIN", "ghp_", "TERRAGUARD_TEST_SECRET")


@dataclass(frozen=True)
class ReportRecord:
    run_id: str
    scenario_id: str
    finding_id: str
    evidence_source: str
    control_id: str
    resource_type: str
    resource_address: str
    normalised_event: str
    detail: str
    run_policy_status: str
    assessment_coverage: float
    severity_band: str
    severity_rule: int
    severity_reason: str
    model_band: str | None
    model_confidence: float | None
    model_agrees: bool | None


class RedactionError(RuntimeError):
    """Raised when a report would carry something that must not leave the machine."""


def assert_clean(report: list[ReportRecord]) -> None:
    """Fail loudly rather than write a report containing a credential."""
    for record in report:
        blob = " ".join(str(v) for v in asdict(record).values())
        for marker in _FORBIDDEN:
            if marker in blob:
                raise RedactionError(
                    f"report record {record.finding_id} contains '{marker}'; "
                    "refusing to write it"
                )


def build_report(
    rows: list[FindingRow], predictor: SeverityPredictor | None = None
) -> list[ReportRecord]:
    """One record per finding, ordered worst first."""
    predictor = predictor or SeverityPredictor()
    predictions: list[Prediction] = predictor.predict(rows)
    records = [
        ReportRecord(
            run_id=row.run_id,
            scenario_id=row.scenario_id,
            finding_id=row.finding_id,
            evidence_source=row.evidence_source,
            control_id=row.control_id,
            resource_type=row.resource_type,
            resource_address=row.resource_address,
            normalised_event=row.normalised_event,
            detail=row.detail,
            run_policy_status=row.run_policy_status,
            assessment_coverage=row.assessment_coverage,
            severity_band=prediction.band,
            severity_rule=prediction.rule_number,
            severity_reason=prediction.rule_reason,
            model_band=prediction.predicted_band,
            model_confidence=prediction.confidence,
            model_agrees=prediction.agrees if prediction.predicted_band else None,
        )
        for row, prediction in zip(rows, predictions, strict=True)
    ]
    records.sort(key=lambda r: (_ORDER.get(r.severity_band, 9), r.control_id, r.finding_id))
    assert_clean(records)
    return records


def write_output(path: str | Path, text: str, *, newline: str | None = None) -> None:
    """Write a report file, creating its directory first.

    The fresh-clone check on 16 Oct failed here: `--output out/report.json` in a new checkout
    raised FileNotFoundError because `out/` did not exist yet.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline=newline)


def render_json(report: list[ReportRecord], path: str | Path | None = None) -> str:
    assert_clean(report)
    payload = {
        "fields": REPORT_FIELDS,
        "counts": {
            band: sum(1 for r in report if r.severity_band == band)
            for band in (HIGH_OR_CRITICAL, MEDIUM, NON_SECURITY_OR_LOW)
        },
        "findings": [asdict(r) for r in report],
    }
    text = json.dumps(payload, indent=2)
    if path:
        write_output(path, text)
    return text


def render_csv(report: list[ReportRecord], path: str | Path | None = None) -> str:
    """One row per finding, columns in REPORT_FIELDS order.

    Written with `csv.DictWriter` rather than by joining strings, because finding details
    contain commas and quotes routinely and a hand-rolled writer would corrupt the file the
    first time a remediation sentence had a comma in it.
    """
    assert_clean(report)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=REPORT_FIELDS, lineterminator="\n")
    writer.writeheader()
    for record in report:
        writer.writerow(asdict(record))
    text = buffer.getvalue()
    if path:
        write_output(path, text, newline="")
    return text


def _column_widths(rows: list[list[str]], headers: list[str]) -> list[int]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    return widths


def render_terminal(report: list[ReportRecord], *, width: int = 64) -> str:
    """A plain-text table.

    Deliberately not using a table library. This output's main home is a CI log, where colour
    codes become escape sequences and box-drawing characters turn into mojibake on a runner
    with a different locale. Plain ASCII survives both.
    """
    assert_clean(report)
    if not report:
        return "No findings.\n"

    headers = ["SEVERITY", "RULE", "CONTROL", "RESOURCE", "DETAIL"]
    rows = [
        [
            r.severity_band,
            str(r.severity_rule),
            r.control_id or "-",
            (r.resource_address or "-")[-34:],
            (r.detail or "")[:width],
        ]
        for r in report
    ]
    widths = _column_widths(rows, headers)
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()
    out = [line, "-" * len(line)]
    for row in rows:
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(len(row))).rstrip())

    counts = {
        band: sum(1 for r in report if r.severity_band == band)
        for band in (HIGH_OR_CRITICAL, MEDIUM, NON_SECURITY_OR_LOW)
    }
    out += [
        "",
        f"{len(report)} finding(s): "
        f"{counts[HIGH_OR_CRITICAL]} high/critical, "
        f"{counts[MEDIUM]} medium, "
        f"{counts[NON_SECURITY_OR_LOW]} non-security/low",
    ]

    coverage = [r.assessment_coverage for r in report]
    if coverage:
        out.append(
            f"assessment coverage {min(coverage):.2f}-{max(coverage):.2f} "
            "- a compliance figure quoted without this cannot be interpreted"
        )

    unsure = [
        r for r in report if r.model_confidence is not None and r.model_confidence < LOW_CONFIDENCE
    ]
    if unsure:
        out.append(f"{len(unsure)} finding(s) ranked with low model confidence")
    disagreed = [r for r in report if r.model_agrees is False]
    if disagreed:
        out.append(
            f"{len(disagreed)} finding(s) where the model disagreed with the rubric "
            "- the rubric was used"
        )
    return "\n".join(out) + "\n"
