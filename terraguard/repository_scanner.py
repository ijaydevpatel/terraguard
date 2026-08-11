"""Find Terraform state, plans and secrets that should never have been committed.

Two things make this more than a filename check:

* it searches **git history**, not just the working tree, because deleting a state file in
  a later commit does not remove it from the repository, and
* it treats a file as exposed if it is *tracked*, regardless of whether .gitignore would
  have caught it today.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import EvidenceSource, Finding, NormalisedEvent

__all__ = ["scan_repository", "scan_paths", "history_paths", "tracked_paths"]

STATE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\.tfstate$"), "TG-P01", "Terraform state file"),
    (re.compile(r"\.tfstate\.backup$"), "TG-P01", "Terraform state backup"),
    (re.compile(r"\.tfstate\.\d+\.backup$"), "TG-P01", "numbered Terraform state backup"),
    (re.compile(r"(^|/)tfplan(\.\w+)?$"), "TG-P07", "saved Terraform plan"),
    (re.compile(r"\.tfplan$"), "TG-P07", "saved Terraform plan"),
    (re.compile(r"(^|/)(tfplan|plan)\.json$"), "TG-P07", "state-derived plan JSON"),
]

SECRET_PATTERNS = [
    (re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"), "AWS access key id"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "GitHub token"),
]

# Synthetic fixtures are deliberately insecure and are the scanner's own test oracle.
FIXTURE_PREFIXES = ("terraform/fixtures/", "tests/fixtures/")


def _run_git(args: list[str], repo: Path) -> list[str]:
    try:
        out = subprocess.run(
            ["git", *args], cwd=str(repo), capture_output=True, text=True, check=True, timeout=60
        )
    except Exception:
        return []
    return [line for line in out.stdout.splitlines() if line.strip()]


def tracked_paths(repo: Path) -> list[str]:
    return _run_git(["ls-files"], repo)


def history_paths(repo: Path) -> list[str]:
    """Every path that has ever existed in the history, including deleted ones."""
    return sorted(
        set(_run_git(["log", "--pretty=format:", "--name-only", "--diff-filter=A"], repo))
    )


def _is_fixture(path: str) -> bool:
    return path.startswith(FIXTURE_PREFIXES)


def scan_paths(
    paths: list[str], *, in_history_only: set[str] | None = None, include_fixtures: bool = False
) -> list[Finding]:
    """Classify a list of repository-relative paths."""
    findings: list[Finding] = []
    for path in paths:
        posix = path.replace("\\", "/")
        if not include_fixtures and _is_fixture(posix):
            continue
        for pattern, control, label in STATE_PATTERNS:
            if not pattern.search(posix):
                continue
            historic = bool(in_history_only and posix in in_history_only)
            findings.append(
                Finding(
                    finding_id=f"repo:{posix}:{control}",
                    evidence_source=EvidenceSource.REPOSITORY,
                    resource_type="repository_file",
                    resource_address=posix,
                    normalised_event=NormalisedEvent.INSECURE_STATE_HANDLING,
                    control_id=control,
                    detail=(
                        f"{label} present in git history only (deleted later)"
                        if historic
                        else f"{label} tracked in the repository"
                    ),
                    explanation=(
                        "State and plan files record every attribute of every resource, "
                        "including values the provider marks sensitive."
                    ),
                    remediation=(
                        "Remove from the working tree and purge from history, then rely on the "
                        "encrypted remote backend."
                    ),
                    raw={"in_history_only": historic},
                )
            )
            break
    return findings


def scan_file_contents(repo: Path, paths: list[str]) -> list[Finding]:
    """Look inside tracked text files for credential-shaped strings."""
    findings: list[Finding] = []
    for path in paths:
        posix = path.replace("\\", "/")
        if _is_fixture(posix):
            continue
        target = repo / path
        try:
            if not target.is_file() or target.stat().st_size > 2_000_000:
                continue
            text = target.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding(
                        finding_id=f"repo:{posix}:secret",
                        evidence_source=EvidenceSource.REPOSITORY,
                        resource_type="repository_file",
                        resource_address=posix,
                        normalised_event=NormalisedEvent.SENSITIVE_DATA_EXPOSURE,
                        control_id="TG-P06",
                        detail=f"{label} found in a tracked file",
                        remediation="Rotate the credential, then purge it from history.",
                    )
                )
                break
    return findings


def scan_repository(repo_root: str | Path, *, include_history: bool = True) -> list[Finding]:
    repo = Path(repo_root)
    tracked = tracked_paths(repo)
    historic: set[str] = set()
    if include_history:
        historic = {p for p in history_paths(repo) if p not in set(tracked)}
    findings = scan_paths(tracked)
    findings += scan_paths(sorted(historic), in_history_only=historic)
    findings += scan_file_contents(repo, tracked)
    return findings
