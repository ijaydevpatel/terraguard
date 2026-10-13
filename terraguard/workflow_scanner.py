"""Read GitHub Actions workflows and flag CI/CD handling that leaks state or over-permits.

The checks map onto four controls:

* TG-P05 - workflow does not publish state or plan artefacts
* TG-P06 - sensitive output is not printed to the job log
* TG-P07 - saved plans are not cached or uploaded
* TG-P08 - GITHUB_TOKEN is scoped, not left at the repository default
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import EvidenceSource, Finding, NormalisedEvent

__all__ = ["scan_workflow_text", "scan_workflow_file", "scan_workflows"]

_ARTEFACT_ACTIONS = ("actions/upload-artifact",)
_CACHE_ACTIONS = ("actions/cache",)
_STATE_HINTS = ("tfstate", "tfplan", "plan.json", ".terraform")
_LONG_LIVED = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")


def _slug(text: str) -> str:
    """A short, stable discriminator taken from the detail.

    One workflow can break one control in two different ways - uploading a plan artefact and
    writing state paths to the cache are both TG-P07 - and keying the id on file plus control
    alone made those collide. The collision inflated the persistence feature, because the
    dataset counted one id twice per run.
    """
    words = re.findall(r"[a-z]{3,}", text.lower())[:4]
    return "-".join(words) or "finding"


def _finding(
    wf: str, control: str, event: NormalisedEvent, detail: str, remediation: str
) -> Finding:
    return Finding(
        finding_id=f"workflow:{wf}:{control}:{_slug(detail)}",
        evidence_source=EvidenceSource.WORKFLOW,
        resource_type="github_workflow",
        resource_address=wf,
        normalised_event=event,
        control_id=control,
        detail=detail,
        remediation=remediation,
    )


def _walk_steps(doc: dict[str, Any]):
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict):
                yield job, step


def scan_workflow_text(text: str, name: str = "workflow.yml") -> list[Finding]:
    try:
        doc = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        return [
            _finding(
                name,
                "TG-P08",
                NormalisedEvent.INSECURE_STATE_HANDLING,
                f"workflow could not be parsed: {exc.__class__.__name__}",
                "Fix the YAML so the workflow can be reviewed.",
            )
        ]
    if not isinstance(doc, dict):
        return []

    findings: list[Finding] = []
    raw = text

    # TG-P08: token scope. Absent permissions means the repository default applies.
    has_top = "permissions" in doc
    has_job = any(
        isinstance(j, dict) and "permissions" in j for j in (doc.get("jobs") or {}).values()
    )
    # Per-job evaluation. A job without its own block inherits the top level, and if there is
    # no top level it inherits the repository default. Checking only the top level missed a
    # job-level write-all entirely, and missed an unscoped job sitting beside a scoped one,
    # which is worse because the file looks careful.
    jobs = {k: v for k, v in (doc.get("jobs") or {}).items() if isinstance(v, dict)}
    for job_name, job in jobs.items():
        scope = job.get("permissions")
        if scope in ("write-all", "read-all"):
            findings.append(
                _finding(
                    name,
                    "TG-P08",
                    NormalisedEvent.PRIVILEGE_EXPANSION,
                    f"job {job_name} sets permissions to {scope}",
                    "Grant only the scopes that job needs.",
                )
            )
        elif "permissions" not in job and has_job and not has_top:
            findings.append(
                _finding(
                    name,
                    "TG-P08",
                    NormalisedEvent.PRIVILEGE_EXPANSION,
                    f"job {job_name} has no permissions block while another job does, so it "
                    "falls back to the repository default",
                    "Give every job an explicit scope, or set a restrictive top-level default.",
                )
            )

    if not has_top and not has_job:
        findings.append(
            _finding(
                name,
                "TG-P08",
                NormalisedEvent.PRIVILEGE_EXPANSION,
                "no permissions block: GITHUB_TOKEN falls back to the repository default",
                "Add an explicit least-privilege permissions block, normally contents: read.",
            )
        )
    elif doc.get("permissions") in ("write-all", "read-all"):
        findings.append(
            _finding(
                name,
                "TG-P08",
                NormalisedEvent.PRIVILEGE_EXPANSION,
                f"permissions set to {doc.get('permissions')}",
                "Grant only the scopes the job needs.",
            )
        )

    for _job, step in _walk_steps(doc):
        uses = str(step.get("uses") or "")
        with_block = str(step.get("with") or "")
        run = str(step.get("run") or "")

        # A broad upload path sweeps up whatever is in the working directory, including a
        # plan or state file written earlier in the job. Matching only on explicit state
        # hints missed `path: .` entirely, which is the widest possible upload.
        # Read the mapping rather than its repr. `str({"path": "."})` is "{'path': '.'}",
        # so a regex written for YAML text matches nothing here, which is why the widest
        # possible upload went unreported.
        with_map = step.get("with") if isinstance(step.get("with"), dict) else {}
        upload_paths = [
            line.strip() for line in str(with_map.get("path") or "").splitlines() if line.strip()
        ]
        broad_path = any(
            p in (".", "./", "*", "./*", "**") or p.startswith("${{ github.workspace")
            for p in upload_paths
        )
        if any(a in uses for a in _ARTEFACT_ACTIONS) and broad_path:
            findings.append(
                _finding(
                    name,
                    "TG-P07",
                    NormalisedEvent.INSECURE_STATE_HANDLING,
                    "an artefact upload covers the whole working directory, which can include "
                    "a plan or state file written earlier in the job",
                    "Upload named files only, never a directory glob.",
                )
            )

        if any(a in uses for a in _ARTEFACT_ACTIONS) and any(
            h in with_block.lower() for h in _STATE_HINTS
        ):
            findings.append(
                _finding(
                    name,
                    "TG-P07",
                    NormalisedEvent.INSECURE_STATE_HANDLING,
                    "a saved plan or state file is uploaded as a workflow artefact",
                    "Never publish plan or state artefacts; publish a sanitised report instead.",
                )
            )
        if any(a in uses for a in _CACHE_ACTIONS) and any(
            h in with_block.lower() for h in _STATE_HINTS
        ):
            findings.append(
                _finding(
                    name,
                    "TG-P07",
                    NormalisedEvent.INSECURE_STATE_HANDLING,
                    "state or plan paths are written to the Actions cache",
                    "Cache only provider plugins, never state or plans.",
                )
            )
        # `terraform show -json` with no redirection prints the whole plan to the job log,
        # where it is readable by anyone who can see the run. Requiring cat or echo as well
        # meant the most direct way of doing it went unreported.
        shows_plan = "terraform show -json" in run.lower()
        redirected = ">" in run or "|" in run
        if shows_plan and not redirected:
            findings.append(
                _finding(
                    name,
                    "TG-P06",
                    NormalisedEvent.SENSITIVE_DATA_EXPOSURE,
                    "terraform show -json prints the plan to the job log",
                    "Redirect to a file and run it through the redactor before publishing.",
                )
            )

        if (
            run
            and any(h in run.lower() for h in ("tfplan.json", "terraform show -json"))
            and ("cat " in run or "echo " in run)
        ):
            findings.append(
                _finding(
                    name,
                    "TG-P06",
                    NormalisedEvent.SENSITIVE_DATA_EXPOSURE,
                    "plan contents are printed to the job log",
                    "Pipe the plan through the redactor before displaying anything.",
                )
            )

    if any(k in raw for k in _LONG_LIVED):
        findings.append(
            _finding(
                name,
                "TG-P09",
                NormalisedEvent.PRIVILEGE_EXPANSION,
                "long-lived AWS access keys referenced in the workflow",
                "Use GitHub OIDC with a narrowly scoped role instead of stored keys.",
            )
        )
    return findings


def scan_workflow_file(path: str | Path) -> list[Finding]:
    p = Path(path)
    return scan_workflow_text(p.read_text(encoding="utf-8"), p.as_posix())


def scan_workflows(root: str | Path) -> list[Finding]:
    root = Path(root)
    out: list[Finding] = []
    for pattern in (".github/workflows/*.yml", ".github/workflows/*.yaml"):
        for path in sorted(root.glob(pattern)):
            out.extend(scan_workflow_file(path))
    return out
