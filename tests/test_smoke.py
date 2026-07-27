"""Phase 0 exit criteria: the package imports, the CLI runs, the version is reachable."""
from __future__ import annotations

import terraguard
from terraguard.cli import build_parser


def test_version_present():
    assert terraguard.__version__


def test_all_modules_import():
    import importlib

    for name in [
        "cli",
        "models",
        "redactor",
        "evidence_collector",
        "plan_parser",
        "drift_extractor",
        "drift_normaliser",
        "repository_scanner",
        "workflow_scanner",
        "policy_engine",
        "feature_builder",
        "severity_rules",
        "model_trainer",
        "model_predictor",
        "report_generator",
    ]:
        importlib.import_module(f"terraguard.{name}")


def test_cli_exposes_planned_subcommands():
    parser = build_parser()
    actions = [a for a in parser._actions if a.dest == "command"]
    assert actions, "no subparsers registered"
    choices = set(actions[0].choices)
    assert {"collect", "scan", "analyse", "train", "evaluate", "report"} <= choices
