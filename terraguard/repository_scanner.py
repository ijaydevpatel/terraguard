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

__all__ = [
    "scan_repository",
    "walk_paths",
    "scan_paths",
    "scan_temp_artefacts",
    "find_sensitive_key_values",
    "history_paths",
    "tracked_paths",
]

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

# Shape-based patterns above only catch credentials that look like credentials. A password
# is just a string, so the only signal is the key it sits under. State files are full of
# these: `"password": "hunter2"` carries no recognisable shape at all.
SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api_?key|access_?key|secret_?key|private_?key|"
    r"credential|client_secret|session_token|connection_string|master_password)",
    re.IGNORECASE,
)

# JSON: "password": "value"   |   HCL/YAML: password = "value" / password: value
_KV_PATTERNS = [
    re.compile(r'"(?P<key>[A-Za-z0-9_.-]+)"\s*:\s*"(?P<value>[^"\n]{1,200})"'),
    re.compile(r"(?P<key>[A-Za-z0-9_.-]+)\s*=\s*\"(?P<value>[^\"\n]{1,200})\""),
    re.compile(r"^\s*(?P<key>[A-Za-z0-9_.-]+)\s*:\s*(?P<value>[^\s#\n][^\n]{0,200})$", re.M),
]

# A value that is a reference, a placeholder or an obvious dummy is not a leak. Flagging
# `password = var.db_password` would make the check useless within a day.
_NOT_A_SECRET = re.compile(
    r"^\s*$|^(var|local|module|data|each|count)\.|^\$\{|^\{\{|"
    r"REPLACE|CHANGE.?ME|YOUR_|EXAMPLE|PLACEHOLDER|TODO|xxx+|\*{3,}|"
    r"^(true|false|null|none|nil)$|^[0-9]+$|^TERRAGUARD_TEST_SECRET_|"
    # GitHub Actions permission scopes read as `id-token: write`. The key contains "token"
    # and the value is a permission level, not a credential. Our own secure workflow
    # fixture was being reported as a secret leak until this was added.
    r"^(read|write|read-all|write-all|none)$",
    re.IGNORECASE,
)


def find_sensitive_key_values(text: str) -> list[tuple[str, str]]:
    """Return (key, redacted_preview) for values sitting under a sensitive key name.

    Only the key name and a length are reported. The value itself is never echoed - a
    scanner that prints the secret it found has moved the problem, not solved it.
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for pattern in _KV_PATTERNS:
        for m in pattern.finditer(text):
            key, value = m.group("key"), m.group("value").strip().strip("\"'")
            if not SENSITIVE_KEY_RE.search(key):
                continue
            if _NOT_A_SECRET.match(value) or len(value) < 4:
                continue
            if key.lower() in seen:
                continue
            seen.add(key.lower())
            out.append((key, f"{len(value)} characters"))
    return out


# Leftover working files that routinely hold state or plan content.
TEMP_ARTEFACT_PATTERNS = [
    (re.compile(r"\.tfstate\.(tmp|temp|old|orig|save|swp)$"), "leftover state working file"),
    (re.compile(r"(^|/)terraform\.tfstate\.\d+$"), "numbered state copy"),
    (re.compile(r"(^|/)(plan|tfplan)\.(out|txt|log)$"), "plan output captured to a file"),
    (re.compile(r"(^|/)\.terraform/terraform\.tfstate$"), "state cached under .terraform"),
    (re.compile(r"(^|/)crash\.log$"), "Terraform crash log (can contain state values)"),
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
        matched = False
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
                matched = True
                break
        if matched:
            continue
        for key, size in find_sensitive_key_values(text):
            findings.append(
                Finding(
                    finding_id=f"repo:{posix}:{key}",
                    evidence_source=EvidenceSource.REPOSITORY,
                    resource_type="repository_file",
                    resource_address=posix,
                    normalised_event=NormalisedEvent.SENSITIVE_DATA_EXPOSURE,
                    control_id="TG-P06",
                    detail=f"value under sensitive key '{key}' ({size}) in a tracked file",
                    explanation=(
                        "A password has no recognisable shape, so the key it sits under is the "
                        "only signal. The value is not reproduced here."
                    ),
                    remediation="Rotate the credential, then purge it from history.",
                )
            )
    return findings


def scan_temp_artefacts(paths: list[str], *, include_fixtures: bool = False) -> list[Finding]:
    """Leftover working files that hold state or plan content.

    Covers the temporary-file and deletion part of the state data lifecycle: a state file
    removed from its normal path can survive as a .tmp, a numbered copy or a crash log.
    """
    findings: list[Finding] = []
    for path in paths:
        posix = path.replace("\\", "/")
        if not include_fixtures and _is_fixture(posix):
            continue
        for pattern, label in TEMP_ARTEFACT_PATTERNS:
            if pattern.search(posix):
                findings.append(
                    Finding(
                        finding_id=f"repo:{posix}:tempfile",
                        evidence_source=EvidenceSource.REPOSITORY,
                        resource_type="repository_file",
                        resource_address=posix,
                        normalised_event=NormalisedEvent.INSECURE_STATE_HANDLING,
                        control_id="TG-P01",
                        detail=f"{label} present",
                        remediation="Delete the file and add its pattern to .gitignore.",
                    )
                )
                break
    return findings


def walk_paths(root: Path) -> list[str]:
    """Every file on disk, for a directory that is not a git repository."""
    return [
        str(p.relative_to(root)).replace("\\", "/")
        for p in root.rglob("*")
        if p.is_file() and ".git/" not in str(p.relative_to(root)).replace("\\", "/")
    ]


def scan_repository(repo_root: str | Path, *, include_history: bool = True) -> list[Finding]:
    """Scan a repository, or any directory.

    `git ls-files` is the right source inside a working tree, because a file being tracked is
    what makes it exposed. Pointed at a directory that is not a repository it returns nothing,
    and the scan used to come back clean - the worst possible answer, since it looks like a
    pass. Outside a repository the filesystem is walked instead.
    """
    repo = Path(repo_root)
    tracked = tracked_paths(repo)
    if not tracked:
        tracked = walk_paths(repo)
        include_history = False
    historic: set[str] = set()
    if include_history:
        historic = {p for p in history_paths(repo) if p not in set(tracked)}
    findings = scan_paths(tracked)
    findings += scan_paths(sorted(historic), in_history_only=historic)
    findings += scan_file_contents(repo, tracked)
    findings += scan_temp_artefacts(tracked)
    return findings
