"""Command-line entry point.

Six subcommands, each one a stage of the pipeline that can be run on its own:

    terraguard scan      repository, workflow and backend evidence from a directory
    terraguard analyse   drift and policy assessment from a plan JSON
    terraguard collect   run Terraform and capture sanitised evidence
    terraguard train     fit the severity models and write the comparison
    terraguard evaluate  score detection, policy and severity over the dataset
    terraguard report    render a sanitised report in terminal, JSON or CSV form

`scan` and `analyse` accept `--fail-on`, which is what makes this usable as a CI gate:
critical and high fail the build, medium warns, low passes, and a control that could not be
assessed warns rather than passing quietly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__

try:
    from rich.console import Console
    from rich.table import Table

    # Unquoted is safe: `from __future__ import annotations` makes this annotation lazy,
    # so `Console` is never looked up at runtime even when the import above failed.
    _console: Console | None = Console(stderr=True)
except Exception:  # rich is optional at runtime
    _console = None

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

GATE_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# The rubric has three classes, and high and critical are deliberately merged because the
# dataset cannot support separating them. The gate still accepts `critical` so that a pipeline
# written against four levels works, but it is an alias for the merged band rather than a
# finer filter. Mapping it to "high" instead meant `--fail-on critical` could never fire at
# all, which is worse than a coarse gate: it silently passes everything.
BAND_TO_GATE = {
    "non_security_or_low": "low",
    "medium": "medium",
    "high_or_critical": "critical",
}


def _echo(message: str) -> None:
    """Diagnostics go to stderr so that stdout stays machine readable.

    `terraguard scan --format json | jq` has to work. Mixing warnings into stdout made the
    JSON unparseable the moment a control came back indeterminate, which is most runs.
    """
    if _console:
        _console.print(message)
    else:
        print(message, file=sys.stderr)


def _rows_from_findings(findings, sources, results, run_id: str, scenario_id: str):
    """Adapt scanner output to the row type the feature builder and report share."""
    from .feature_builder import FindingRow
    from .models import PolicyStatus
    from .policy_engine import assessment_coverage

    non_compliant = [r for r in results if r.status is PolicyStatus.NON_COMPLIANT]
    status = "non_compliant" if non_compliant else "compliant"
    coverage = round(assessment_coverage(results), 3)
    del sources
    return [
        FindingRow(
            run_id=run_id,
            scenario_id=scenario_id,
            finding_id=f.finding_id,
            evidence_source=f.evidence_source.value,
            control_id=f.control_id or "",
            normalised_event=f.normalised_event.value if f.normalised_event else "",
            resource_address=f.resource_address or "",
            detail=f.detail or "",
            resource_type=f.resource_type or "",
            findings_in_run=len(findings),
            assessment_coverage=coverage,
            run_policy_status=status,
            persistence_across_runs=1,
        )
        for f in findings
    ]


def _render(report, args) -> None:
    from .report_generator import render_csv, render_json, render_terminal

    if args.format == "json":
        text = render_json(report, args.output)
    elif args.format == "csv":
        text = render_csv(report, args.output)
    else:
        text = render_terminal(report)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
    if not args.output or args.format == "terminal":
        print(text)
    if args.output:
        _echo(f"written: {args.output}")


def _gate(report, results, threshold: str | None) -> int:
    """Apply the severity gate. Returns the process exit code."""
    from .models import PolicyStatus

    indeterminate = [r for r in results if r.status is PolicyStatus.INDETERMINATE]
    if indeterminate:
        _echo(
            f"warning: {len(indeterminate)} control(s) could not be assessed - "
            "missing evidence is not the same as compliance"
        )
    if not threshold:
        return EXIT_OK

    if threshold == "critical":
        _echo(
            "note: the severity rubric merges high and critical, so --fail-on critical "
            "behaves identically to --fail-on high"
        )
    floor = GATE_ORDER[threshold]
    breached = [r for r in report if GATE_ORDER[BAND_TO_GATE[r.severity_band]] >= floor]
    warned = [
        r
        for r in report
        if GATE_ORDER[BAND_TO_GATE[r.severity_band]] < floor
        and BAND_TO_GATE[r.severity_band] == "medium"
    ]
    if warned:
        _echo(f"warning: {len(warned)} finding(s) below the {threshold} gate")
    if breached:
        _echo(f"FAIL: {len(breached)} finding(s) at or above {threshold}")
        return EXIT_FINDINGS
    _echo(f"pass: nothing at or above {threshold}")
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    from .backend_scanner import scan_backend_config
    from .models import EvidenceSource
    from .policy_engine import assess, load_controls
    from .report_generator import build_report
    from .repository_scanner import scan_repository
    from .workflow_scanner import scan_workflows

    root = Path(args.path)
    if not root.is_dir():
        _echo(f"not a directory: {root}")
        return EXIT_USAGE

    findings = scan_repository(root, include_history=not args.no_history)
    sources = {EvidenceSource.REPOSITORY}
    if (root / ".github" / "workflows").exists():
        findings += scan_workflows(root)
        sources.add(EvidenceSource.WORKFLOW)
    backend = root / "backend.tf"
    if backend.exists():
        findings += scan_backend_config(backend.read_text(encoding="utf-8"))
        sources.add(EvidenceSource.BACKEND_CONFIG)

    controls = load_controls(args.policies, include_optional=args.include_optional)
    results = assess(controls, findings, available_evidence=sources)
    rows = _rows_from_findings(findings, sources, results, "scan", args.scenario_id or "scan")
    report = build_report(rows, _predictor(args))
    _render(report, args)
    return _gate(report, results, args.fail_on)


def cmd_analyse(args: argparse.Namespace) -> int:
    from .drift_extractor import extract_from_plan
    from .drift_normaliser import normalise
    from .models import EvidenceSource
    from .policy_engine import assess, load_controls
    from .report_generator import build_report

    plan = json.loads(Path(args.plan_json).read_text(encoding="utf-8"))
    findings = normalise(extract_from_plan(plan), scenario_id=args.scenario_id)
    sources = {EvidenceSource.TERRAFORM_PLAN_JSON}
    controls = load_controls(args.policies, include_optional=args.include_optional)
    results = assess(controls, findings, available_evidence=sources)
    rows = _rows_from_findings(findings, sources, results, "analyse", args.scenario_id or "analyse")
    report = build_report(rows, _predictor(args))
    _render(report, args)
    return _gate(report, results, args.fail_on)


def _predictor(args: argparse.Namespace):
    from .model_predictor import SeverityPredictor

    model = getattr(args, "model", None)
    encoder = getattr(args, "encoder", None)
    if model and encoder:
        return SeverityPredictor.from_artefacts(model, encoder)
    return SeverityPredictor()


def cmd_train(args: argparse.Namespace) -> int:
    from .model_trainer import run_comparison

    report = run_comparison(args.findings, args.observations, args.output)
    _echo(
        f"{report.n_findings} findings, {report.n_groups} templates, "
        f"{report.n_splits} folds -> {args.output}"
    )
    for score in report.scores:
        _echo(
            f"  {score['name']:22s} macro F1 {score['macro_f1']}  "
            f"recall on high/critical {score['high_risk_recall']}"
        )
    for warning in report.warnings:
        _echo(f"  warning: {warning}")
    return EXIT_OK


def cmd_evaluate(args: argparse.Namespace) -> int:
    import csv as _csv
    import statistics
    from collections import Counter

    observations = list(_csv.DictReader(open(args.observations, encoding="utf-8")))
    if not observations:
        _echo("no observations to evaluate")
        return EXIT_USAGE
    detection = sum(o["detection_match"] == "True" for o in observations)
    policy = sum(o["policy_match"] == "True" for o in observations)
    clean = [o for o in observations if o["expected_policy_status"] == "compliant"]
    # A false alert is a *security* finding on a scenario that should raise none. The tag and
    # description drift families legitimately produce a non-security finding and stay
    # compliant, so counting every finding here would conflate "noticed a change" with
    # "cried wolf", and the figure would look alarming while nothing was wrong.
    false_alerts = sum(
        1 for o in clean if o["deterministic_severity"] in ("high_or_critical", "medium")
    )
    noticed = sum(int(o["findings_count"]) for o in clean)
    times = [float(o["processing_time_ms"]) for o in observations]
    coverage = [float(o["assessment_coverage"]) for o in observations]
    summary = {
        "observations": len(observations),
        "templates": len({o["scenario_id"] for o in observations}),
        "detection_match": f"{detection}/{len(observations)}",
        "policy_match": f"{policy}/{len(observations)}",
        "negative_controls": len(clean),
        "false_alerts": false_alerts,
        "non_security_findings_on_negative_controls": noticed,
        "processing_ms": {
            "min": round(min(times), 1),
            "median": round(statistics.median(times), 1),
            "max": round(max(times), 1),
        },
        "assessment_coverage": {"min": min(coverage), "max": max(coverage)},
        "by_band": dict(Counter(o["deterministic_severity"] or "none" for o in observations)),
    }
    print(json.dumps(summary, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        _echo(f"written: {args.output}")
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    import csv as _csv

    from .feature_builder import load_rows
    from .report_generator import build_report

    rows = load_rows(args.findings, args.observations)
    if args.scenario_id:
        rows = [r for r in rows if r.scenario_id == args.scenario_id]
    report = build_report(rows, _predictor(args))
    del _csv
    _render(report, args)
    return _gate(report, [], args.fail_on)


def cmd_collect(args: argparse.Namespace) -> int:
    from .evidence_collector import collect, collect_from_plan_json

    if args.plan_json:
        bundle = collect_from_plan_json(
            args.plan_json, args.output, repo_root=args.repo_root, scenario_id=args.scenario_id
        )
    else:
        bundle = collect(
            args.terraform_dir,
            args.output,
            repo_root=args.repo_root,
            scenario_id=args.scenario_id,
            refresh_only=not args.no_refresh_only,
            run_init=not args.skip_init,
        )

    bundle_path = Path(args.output) / f"{bundle.run_id}.evidence.json"
    bundle_path.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")

    if _console:
        table = Table(title=f"Evidence bundle {bundle.run_id}", show_lines=False)
        table.add_column("Field")
        table.add_column("Value", overflow="fold")
        table.add_row("terraform dir", bundle.terraform_dir)
        table.add_row("sanitised plan", str(bundle.plan_json_sanitised_path))
        table.add_row("tracked files", str(len(bundle.repository_files)))
        table.add_row("workflow files", ", ".join(bundle.workflow_files) or "none")
        table.add_row("backend config", "captured" if bundle.backend_config_raw else "none")
        table.add_row("commands", "; ".join(bundle.commands_run))
        table.add_row("duration", f"{bundle.duration_ms:.0f} ms")
        for warning in bundle.warnings:
            table.add_row("warning", warning)
        _console.print(table)
    else:
        print(json.dumps(json.loads(bundle.model_dump_json()), indent=2))

    _echo(
        f"[green]bundle written:[/green] {bundle_path}" if _console else f"written: {bundle_path}"
    )
    return EXIT_OK


def _add_output_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", choices=("terminal", "json", "csv"), default="terminal")
    p.add_argument("--output", help="write the report to this path as well")
    p.add_argument("--policies", default="policies")
    p.add_argument("--include-optional", action="store_true", help="assess TG-P09 to TG-P13 too")
    p.add_argument("--fail-on", choices=("low", "medium", "high", "critical"))
    p.add_argument("--model", help="trained model pickle, optional")
    p.add_argument("--encoder", help="fitted encoder pickle, optional")
    p.add_argument("--scenario-id")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="terraguard", description=__doc__)
    parser.add_argument("--version", action="version", version=f"terraguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a repository directory for exposed state")
    scan_p.add_argument("path", nargs="?", default=".")
    scan_p.add_argument("--no-history", action="store_true", help="skip the git history search")
    _add_output_flags(scan_p)
    scan_p.set_defaults(func=cmd_scan)

    analyse_p = sub.add_parser("analyse", help="assess drift from a plan JSON")
    analyse_p.add_argument("--plan-json", required=True)
    _add_output_flags(analyse_p)
    analyse_p.set_defaults(func=cmd_analyse)

    collect_p = sub.add_parser("collect", help="run Terraform and capture sanitised evidence")
    collect_p.add_argument("--terraform-dir", default="terraform/baseline")
    collect_p.add_argument("--plan-json", help="offline mode: use an existing plan JSON")
    collect_p.add_argument("--output", default="evidence")
    collect_p.add_argument("--repo-root", default=".")
    collect_p.add_argument("--scenario-id")
    collect_p.add_argument("--skip-init", action="store_true")
    collect_p.add_argument("--no-refresh-only", action="store_true")
    collect_p.set_defaults(func=cmd_collect)

    train_p = sub.add_parser("train", help="fit the severity models")
    train_p.add_argument("--findings", default="datasets/findings.csv")
    train_p.add_argument("--observations", default="datasets/observations.csv")
    train_p.add_argument("--output", default="results")
    train_p.set_defaults(func=cmd_train)

    eval_p = sub.add_parser("evaluate", help="score detection and policy over the dataset")
    eval_p.add_argument("--observations", default="datasets/observations.csv")
    eval_p.add_argument("--output")
    eval_p.set_defaults(func=cmd_evaluate)

    report_p = sub.add_parser("report", help="render a report from the collected dataset")
    report_p.add_argument("--findings", default="datasets/findings.csv")
    report_p.add_argument("--observations", default="datasets/observations.csv")
    _add_output_flags(report_p)
    report_p.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
