"""Phase 1: run Terraform, capture evidence, sanitise it, delete the dangerous bits.

Invariants:
  * The binary saved plan never outlives this function.
  * Raw plan JSON is written only inside a temp directory and deleted afterwards.
  * The only artefact that reaches the output directory is the sanitised plan JSON.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .models import EvidenceBundle
from .redactor import redact_plan_obj, scrub_text

WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
BACKEND_FILES = ("backend.tf", "backend.tf.json", "providers.tf", "main.tf")
TERRAFORM_BIN = os.environ.get("TERRAGUARD_TERRAFORM_BIN", "terraform")


class TerraformError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path, timeout: int = 900) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False
    )
    if proc.returncode != 0:
        raise TerraformError(
            f"{' '.join(args)} failed ({proc.returncode}): {scrub_text(proc.stderr[-2000:])}"
        )
    return proc


def terraform_version(cwd: Path) -> str | None:
    try:
        out = _run([TERRAFORM_BIN, "version", "-json"], cwd).stdout
        return json.loads(out).get("terraform_version")
    except Exception:
        return None


def collect_repository_evidence(repo_root: Path) -> list[str]:
    """Tracked files according to git, falling back to a filesystem walk."""
    try:
        proc = subprocess.run(
            ["git", "ls-files"], cwd=str(repo_root), capture_output=True, text=True, check=True
        )
        return [line for line in proc.stdout.splitlines() if line]
    except Exception:
        return [
            str(p.relative_to(repo_root))
            for p in repo_root.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]


def collect_workflow_evidence(repo_root: Path) -> list[str]:
    files: list[str] = []
    for pattern in WORKFLOW_GLOBS:
        files.extend(str(p.relative_to(repo_root)) for p in repo_root.glob(pattern))
    return sorted(files)


def collect_backend_config(terraform_dir: Path) -> str | None:
    parts: list[str] = []
    for name in BACKEND_FILES:
        path = terraform_dir / name
        if path.exists():
            parts.append(f"# ---- {name} ----\n{path.read_text(encoding='utf-8')}")
    return "\n".join(parts) if parts else None


def collect(
    terraform_dir: str | Path,
    output_dir: str | Path,
    *,
    repo_root: str | Path | None = None,
    scenario_id: str | None = None,
    refresh_only: bool = True,
    run_init: bool = True,
    salt: str = "",
) -> EvidenceBundle:
    """Run the Terraform evidence pipeline and return a bundle of sanitised artefacts."""
    started = time.perf_counter()
    terraform_dir = Path(terraform_dir).resolve()
    output_dir = Path(output_dir).resolve()
    repo_root = Path(repo_root).resolve() if repo_root else terraform_dir.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = f"{scenario_id or 'run'}-{uuid.uuid4().hex[:8]}"
    commands: list[str] = []
    warnings: list[str] = []

    tmpdir = Path(tempfile.mkdtemp(prefix="terraguard-"))
    plan_bin = tmpdir / "tfplan"
    raw_json = tmpdir / "tfplan.raw.json"
    sanitised = output_dir / f"{run_id}.plan.sanitised.json"

    try:
        if run_init:
            _run([TERRAFORM_BIN, "init", "-input=false", "-no-color"], terraform_dir)
            commands.append("terraform init")

        _run([TERRAFORM_BIN, "validate", "-no-color"], terraform_dir)
        commands.append("terraform validate")

        plan_args = [TERRAFORM_BIN, "plan", "-input=false", "-no-color", f"-out={plan_bin}"]
        if refresh_only:
            plan_args.insert(2, "-refresh-only")
        else:
            plan_args.insert(2, "-refresh=true")
        _run(plan_args, terraform_dir)
        commands.append(" ".join(a for a in plan_args if not a.startswith("-out")))

        show = _run([TERRAFORM_BIN, "show", "-json", str(plan_bin)], terraform_dir)
        commands.append("terraform show -json")
        raw_json.write_text(show.stdout, encoding="utf-8")

        plan_obj = json.loads(show.stdout)
        sanitised.write_text(
            json.dumps(redact_plan_obj(plan_obj, salt=salt), indent=2), encoding="utf-8"
        )

        if not (plan_obj.get("resource_drift") or plan_obj.get("resource_changes")):
            warnings.append("plan contained no resource_drift and no resource_changes")

        return EvidenceBundle(
            run_id=run_id,
            scenario_id=scenario_id,
            terraform_dir=str(terraform_dir),
            plan_json_path=None,  # raw JSON is deliberately not retained
            plan_json_sanitised_path=str(sanitised),
            repository_files=collect_repository_evidence(repo_root),
            workflow_files=collect_workflow_evidence(repo_root),
            backend_config_raw=collect_backend_config(terraform_dir),
            terraform_version=terraform_version(terraform_dir),
            commands_run=commands,
            warnings=warnings,
            duration_ms=(time.perf_counter() - started) * 1000,
        )
    finally:
        # Binary plan and raw JSON are the two highest-risk artefacts. Always destroy them.
        shutil.rmtree(tmpdir, ignore_errors=True)


def collect_from_plan_json(
    plan_json_path: str | Path,
    output_dir: str | Path,
    *,
    repo_root: str | Path | None = None,
    scenario_id: str | None = None,
    salt: str = "",
) -> EvidenceBundle:
    """Offline path: build a bundle from an existing plan JSON, no Terraform or AWS needed.

    This is what keeps every downstream module testable with zero credentials.
    """
    started = time.perf_counter()
    plan_json_path = Path(plan_json_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    repo_root = Path(repo_root).resolve() if repo_root else plan_json_path.parent

    run_id = f"{scenario_id or 'offline'}-{uuid.uuid4().hex[:8]}"
    plan_obj = json.loads(plan_json_path.read_text(encoding="utf-8"))
    sanitised = output_dir / f"{run_id}.plan.sanitised.json"
    sanitised.write_text(
        json.dumps(redact_plan_obj(plan_obj, salt=salt), indent=2), encoding="utf-8"
    )

    return EvidenceBundle(
        run_id=run_id,
        scenario_id=scenario_id,
        terraform_dir=str(plan_json_path.parent),
        plan_json_sanitised_path=str(sanitised),
        repository_files=collect_repository_evidence(repo_root),
        workflow_files=collect_workflow_evidence(repo_root),
        backend_config_raw=collect_backend_config(plan_json_path.parent),
        commands_run=["offline: existing plan json"],
        duration_ms=(time.perf_counter() - started) * 1000,
    )
