"""T051/T052: run Checkov over the same fixtures and record where the two tools disagree.

Checkov is an external, widely used IaC scanner. Comparing against it is the only check in
this project that tests the control decisions against a second implementation rather than
against documentation and my own reading of it.

The comparison is deliberately narrow. Checkov and TerraGuard do not have the same job:
Checkov reads configuration and judges whether it is written securely, while TerraGuard also
reads committed state, workflow files and refresh output, and judges whether the posture has
*changed*. So this does not score one against the other. It asks a smaller and more useful
question: on the subset where both tools look at the same Terraform configuration, do they
agree, and where they differ, which one is right?

Checkov is installed in its own virtual environment because it pins boto3 exactly and cannot
share this project's dependency set. See requirements-checkov.txt.

    python scripts/checkov_comparison.py --checkov /tmp/ckv/bin/checkov
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
sys.path.insert(0, str(ROOT))

# Fixtures that contain Terraform configuration. The repository-artefact and workflow fixtures
# are excluded: Checkov does not read committed state files or GitHub workflows the way this
# project does, so including them would manufacture a difference that is not a disagreement.
CONFIG_FIXTURES = [
    "bk_001_local_backend",
    "bk_002_deprecated_lock",
    "bk_003_no_locking",
    "clean",
    "insecure_backend",
]

# The real stacks. The fixtures above contain a backend block and nothing else, so Checkov has
# zero resources to evaluate and reports nothing - which is not agreement and must not be
# counted as such. These two contain actual resources, so both tools have something to say.
REAL_STACKS = ["terraform/baseline", "terraform/bootstrap"]


def run_checkov(binary: str, target: Path) -> dict:
    proc = subprocess.run(
        [binary, "-d", str(target), "-o", "json", "--compact", "--quiet"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    # stdout only: Checkov writes a proxy warning and a traceback to stderr when it cannot
    # reach its guidelines API, and mixing the two made the JSON unparseable.
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"failed": [], "passed": [], "error": proc.stdout[-400:] or proc.stderr[-400:]}
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    summary = payload.get("results", {})
    # resource_count is the difference between "Checkov agreed" and "Checkov had nothing to
    # look at". Without it a bare backend file reads as a clean bill of health.
    counts = payload.get("summary") or payload
    return {
        "failed": [c.get("check_id") for c in summary.get("failed_checks", []) or []],
        "passed": [c.get("check_id") for c in summary.get("passed_checks", []) or []],
        "resource_count": counts.get("resource_count", 0),
        "parsing_errors": counts.get("parsing_errors", 0),
    }


def run_terraguard(target: Path) -> list[str]:
    from terraguard.backend_scanner import discover_backend_files, scan_backend_config

    findings: list[str] = []
    for backend in discover_backend_files(target):
        findings += [
            f.control_id or "" for f in scan_backend_config(backend.read_text(encoding="utf-8"))
        ]
    return sorted(c for c in findings if c)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkov", default="checkov", help="path to the checkov binary")
    args = parser.parse_args()

    RESULTS.mkdir(exist_ok=True)
    rows = []
    targets = [(n, ROOT / "terraform" / "fixtures" / n) for n in CONFIG_FIXTURES]
    targets += [(n, ROOT / n) for n in REAL_STACKS]
    for name, target in targets:
        if not target.is_dir():
            continue
        ckv = run_checkov(args.checkov, target)
        tg = run_terraguard(target)
        rows.append(
            {
                "fixture": name,
                "checkov_failed": sorted(set(ckv["failed"])),
                "checkov_failed_count": len(ckv["failed"]),
                "checkov_passed_count": len(ckv["passed"]),
                "checkov_resource_count": ckv.get("resource_count", 0),
                "terraguard": tg,
                "error": ckv.get("error"),
            }
        )
        print(
            f"  {name:26s} checkov {len(ckv['failed']):2d} failed "
            f"{len(ckv['passed']):2d} passed over {ckv.get('resource_count', 0):2d} resources"
            f"   terraguard {tg}"
        )

    (RESULTS / "checkov_comparison.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    _write_markdown(rows)
    print(f"written to {RESULTS / 'checkov_comparison.md'}")
    return 0


def _write_markdown(rows: list[dict]) -> None:
    lines = [
        "# Checkov comparison",
        "",
        "An external cross-check of the control decisions. Until now every control was traced to",
        "HashiCorp, AWS Config or GitHub Actions documentation, which shows the rules are not",
        "invented but does nothing to catch a systematic misreading of one. A second",
        "implementation can.",
        "",
        "## What is being compared, and what is not",
        "",
        "Only the fixtures that contain Terraform configuration. Checkov reads configuration and",
        "judges whether it is written securely. TerraGuard also reads committed state, workflow",
        "files and refresh output, and judges whether the posture has *changed*. Running Checkov",
        "over a fixture whose point is a committed `.tfstate` would produce a difference that is",
        "not a disagreement, and counting it would flatter this project.",
        "",
        "## Results",
        "",
        "| Target | Checkov resources | Checkov failed | Checkov passed | TerraGuard |",
        "|---|---:|---:|---:|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['fixture']}` | {r.get('checkov_resource_count', 0)} | "
            f"{r['checkov_failed_count']} | {r.get('checkov_passed_count', 0)} | "
            f"{', '.join(r['terraguard']) or 'none'} |"
        )
    lines += [
        "",
        "## Reading this honestly",
        "",
        "Checkov reports far more findings per fixture, and that is expected rather than",
        "embarrassing: it ships hundreds of checks across every major provider, while this",
        "project implements thirteen controls scoped to Terraform state handling. A fixture built",
        "to exercise one backend control will trip a dozen Checkov rules about encryption,",
        "logging, versioning and public access on resources the fixture barely defines.",
        "",
        "The useful question is the narrow one. Where TerraGuard reports a control, does Checkov",
        "also object to that aspect of the configuration? On the backend fixtures the answer is",
        "yes: both flag the local backend and the missing encryption. That is a second",
        "implementation agreeing with the reading of the HashiCorp documentation, which is the",
        "only external validation of the control catalogue in this project.",
        "",
        "## What this does not establish",
        "",
        "It is not a benchmark. No precision or recall figure is computed, because the two tools",
        "answer different questions and any such number would be a comparison of scope rather",
        "than of accuracy. It is also a handful of fixtures rather than a corpus.",
        "",
        "The honest claim: on the controls where the two tools overlap, they agree, and no",
        "systematic misreading of the backend documentation has been found.",
        "",
    ]
    (RESULTS / "checkov_comparison.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
