"""Command-line entry point. Phases 2-9 attach their subcommands here."""

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
    _console: Console | None = Console()
except Exception:  # rich is optional at runtime
    _console = None


def _echo(message: str) -> None:
    if _console:
        _console.print(message)
    else:
        print(message)


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
    return 0


def _not_yet(phase: str):
    def handler(args: argparse.Namespace) -> int:
        _echo(f"[yellow]not implemented yet[/yellow] - scheduled in {phase}")
        return 2

    return handler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="terraguard", description=__doc__)
    parser.add_argument("--version", action="version", version=f"terraguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    collect_p = sub.add_parser("collect", help="run Terraform and capture sanitised evidence")
    collect_p.add_argument("--terraform-dir", default="terraform/baseline")
    collect_p.add_argument("--plan-json", help="offline mode: use an existing plan JSON")
    collect_p.add_argument("--output", default="evidence")
    collect_p.add_argument("--repo-root", default=".")
    collect_p.add_argument("--scenario-id")
    collect_p.add_argument("--skip-init", action="store_true")
    collect_p.add_argument("--no-refresh-only", action="store_true")
    collect_p.set_defaults(func=cmd_collect)

    for name, help_text, phase in [
        ("scan", "run repository, workflow and backend scanners", "Phase 3"),
        ("analyse", "parse drift, normalise events, evaluate controls", "Phase 2-4"),
        ("train", "train the severity models", "Phase 7"),
        ("evaluate", "score detection, policy and severity performance", "Phase 10"),
        ("report", "render a sanitised report", "Phase 8"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=_not_yet(phase))

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
