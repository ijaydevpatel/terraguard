#!/usr/bin/env python3
"""Run one scenario end to end and append a row to the observation dataset.

The harness reads the manifest first and never looks at it again until the end. That
ordering is deliberate: detection must not be able to see the expected answer while it is
deciding. Comparing the two only happens after the run, when the row is written.

Offline scenarios (state-security and clean controls) need no AWS. Drift scenarios need a
deployed baseline and are skipped with an explicit reason if credentials are absent, so a
partial dataset is visibly partial rather than quietly short.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from terraguard.backend_scanner import scan_backend_config  # noqa: E402
from terraguard.drift_extractor import extract_from_plan  # noqa: E402
from terraguard.drift_normaliser import normalise  # noqa: E402
from terraguard.models import UTC, EvidenceSource, PolicyStatus  # noqa: E402
from terraguard.policy_engine import assess, assessment_coverage, load_controls  # noqa: E402
from terraguard.repository_scanner import scan_paths  # noqa: E402
from terraguard.workflow_scanner import scan_workflows  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "datasets" / "scenario_manifests"
OBSERVATIONS = ROOT / "datasets" / "observations.csv"
FINDINGS = ROOT / "datasets" / "findings.csv"

FIELDS = [
    "run_id",
    "scenario_id",
    "scenario_group",
    "tier",
    "run_started",
    "evidence_source",
    "resource_type",
    "fixture",
    "expected_drift",
    "detected_drift",
    "expected_control",
    "expected_policy_status",
    "actual_policy_status",
    "expected_severity_band",
    "deterministic_severity",
    "findings_count",
    "controls_assessed",
    "assessment_coverage",
    "detection_match",
    "policy_match",
    "processing_time_ms",
    "notes",
]

FIXTURES = {
    "ST-001": "st_001_state_committed",
    "ST-002": "st_002_backup_committed",
    "WF-001": "wf_001_plan_artefact",
    "BK-001": "bk_001_local_backend",
    "CLEAN-002": "clean_002_workflow",
    "CLEAN-001": "clean",
}


def load_manifest(scenario_id: str) -> dict:
    path = MANIFESTS / f"{scenario_id}.yaml"
    if not path.exists():
        raise SystemExit(f"no manifest for {scenario_id} - a run without ground truth is invalid")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def collect_offline(fixture_dir: Path):
    """Gather evidence from a fixture directory. No AWS, no Terraform."""
    findings = []
    sources: set[EvidenceSource] = set()

    tracked = [
        str(p.relative_to(fixture_dir)).replace("\\", "/")
        for p in fixture_dir.rglob("*")
        if p.is_file()
    ]
    if tracked:
        sources.add(EvidenceSource.REPOSITORY)
        findings += scan_paths(tracked, include_fixtures=True)

    if (fixture_dir / ".github" / "workflows").exists():
        sources.add(EvidenceSource.WORKFLOW)
        findings += scan_workflows(fixture_dir)

    backend = fixture_dir / "backend.tf"
    if backend.exists():
        sources.add(EvidenceSource.BACKEND_CONFIG)
        findings += scan_backend_config(backend.read_text(encoding="utf-8"))

    return findings, sources


def collect_plan(plan_path: Path, scenario_id: str):
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    findings = normalise(extract_from_plan(plan), scenario_id=scenario_id)
    return findings, {EvidenceSource.TERRAFORM_PLAN_JSON}


def run(scenario_id: str, *, plan_json: Path | None, run_id: str, dry_run: bool) -> dict:
    manifest = load_manifest(scenario_id)
    started = datetime.now(UTC)
    clock = time.perf_counter()

    if plan_json:
        findings, sources = collect_plan(plan_json, scenario_id)
        fixture = plan_json.name
    else:
        name = FIXTURES.get(scenario_id)
        if not name:
            raise SystemExit(
                f"{scenario_id} needs a deployed baseline and a plan JSON; "
                "pass --plan-json, or run an offline scenario"
            )
        fixture_dir = ROOT / "terraform" / "fixtures" / name
        findings, sources = collect_offline(fixture_dir)
        fixture = name

    controls = load_controls(ROOT / "policies")
    results = assess(controls, findings, available_evidence=sources)
    elapsed_ms = (time.perf_counter() - clock) * 1000

    non_compliant = [r for r in results if r.status is PolicyStatus.NON_COMPLIANT]
    detected = bool(findings)
    expected_drift = bool(manifest.get("expected_drift"))
    expected_status = manifest.get("expected_policy_status")
    actual_status = "non_compliant" if non_compliant else "compliant"
    expected_control = (manifest.get("expected_control") or "").strip()

    if expected_control:
        control_hit = any(r.control_id == expected_control for r in non_compliant)
    else:
        control_hit = not non_compliant

    row = {
        "run_id": run_id,
        "scenario_id": scenario_id,
        "scenario_group": manifest.get("scenario_group"),
        "tier": manifest.get("tier"),
        "run_started": started.isoformat(timespec="seconds"),
        "evidence_source": ",".join(sorted(s.value for s in sources)),
        "resource_type": manifest.get("resource_type"),
        "fixture": fixture,
        "expected_drift": expected_drift,
        "detected_drift": detected,
        "expected_control": expected_control,
        "expected_policy_status": expected_status,
        "actual_policy_status": actual_status,
        "expected_severity_band": manifest.get("expected_severity_band"),
        "deterministic_severity": "",  # filled in Phase 6, severity_rules.py
        "findings_count": len(findings),
        "controls_assessed": len(results),
        "assessment_coverage": round(assessment_coverage(results), 3),
        "detection_match": control_hit,
        "policy_match": actual_status == expected_status,
        "processing_time_ms": round(elapsed_ms, 2),
        "notes": "" if control_hit else "expected control not raised - investigate",
    }

    if not dry_run:
        _append(OBSERVATIONS, FIELDS, [row])
        _append(
            FINDINGS,
            [
                "run_id",
                "scenario_id",
                "finding_id",
                "evidence_source",
                "control_id",
                "normalised_event",
                "resource_address",
                "detail",
            ],
            [
                {
                    "run_id": run_id,
                    "scenario_id": scenario_id,
                    "finding_id": f.finding_id,
                    "evidence_source": f.evidence_source.value,
                    "control_id": f.control_id or "",
                    "normalised_event": f.normalised_event.value if f.normalised_event else "",
                    "resource_address": f.resource_address or "",
                    "detail": f.detail,
                }
                for f in findings
            ],
        )
    return row


def _append(path: Path, fields: list[str], rows: list[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if new:
            writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scenario_id", nargs="+")
    ap.add_argument(
        "--plan-json", type=Path, help="for drift scenarios needing a deployed baseline"
    )
    ap.add_argument("--run-id", help="defaults to a generated id per scenario")
    ap.add_argument("--dry-run", action="store_true", help="run but write nothing")
    args = ap.parse_args()

    mismatches = 0
    for sid in args.scenario_id:
        run_id = args.run_id or f"{sid}-{uuid.uuid4().hex[:8]}"
        row = run(sid, plan_json=args.plan_json, run_id=run_id, dry_run=args.dry_run)
        flag = "ok " if row["detection_match"] and row["policy_match"] else "MISS"
        mismatches += 0 if flag == "ok " else 1
        print(
            f"{flag} {sid:10s} findings={row['findings_count']:2d} "
            f"policy={row['actual_policy_status']:14s} "
            f"coverage={row['assessment_coverage']:.2f} "
            f"{row['processing_time_ms']:7.2f} ms"
        )
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
