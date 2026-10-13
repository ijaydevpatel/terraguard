"""Assess the Terraform state backend.

Runs two ways on purpose:

* **static** - parse ``backend.tf`` when there are no AWS credentials. Every module in this
  project must work offline, so this is the default path.
* **live**   - query the bucket with boto3 when credentials are present.

A static parse cannot see whether the bucket is actually encrypted, only whether the
configuration asks for it. Where the answer is genuinely unknown the finding says so rather
than guessing, which is what feeds the Indeterminate policy outcome.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import EvidenceSource, Finding, NormalisedEvent

__all__ = [
    "parse_backend_block",
    "scan_backend_config",
    "scan_backend_live",
    "discover_backend_files",
    "strip_comments",
]

_BACKEND_RE = re.compile(r'backend\s+"(?P<kind>\w+)"\s*\{(?P<body>[^}]*)\}', re.DOTALL)
_ATTR_RE = re.compile(r'(?P<key>\w+)\s*=\s*"?(?P<value>[^"\n]+)"?')


def parse_backend_block(text: str) -> dict[str, str] | None:
    m = _BACKEND_RE.search(text or "")
    if not m:
        return None
    attrs = {"backend_type": m.group("kind")}
    for am in _ATTR_RE.finditer(m.group("body")):
        attrs[am.group("key")] = am.group("value").strip()
    return attrs


def _f(
    control: str,
    detail: str,
    remediation: str,
    event=NormalisedEvent.INSECURE_STATE_HANDLING,
    address="backend.tf",
    indeterminate: bool = False,
) -> Finding:
    return Finding(
        finding_id=f"backend:{address}:{control}",
        evidence_source=EvidenceSource.BACKEND_CONFIG,
        resource_type="terraform_backend",
        resource_address=address,
        normalised_event=event,
        control_id=control,
        detail=detail,
        remediation=remediation,
        raw={"indeterminate": indeterminate},
    )


def strip_comments(text: str) -> str:
    """Remove HCL comments before parsing.

    A fully commented-out backend block passed the static check, because the parser only ever
    searched for the words. A commented backend is not a backend: the state is local and the
    file merely looks reassuring, which is the worst combination.
    """
    out: list[str] = []
    in_block_comment = False
    for line in text.splitlines():
        if in_block_comment:
            if "*/" in line:
                line = line.split("*/", 1)[1]
                in_block_comment = False
            else:
                continue
        while "/*" in line:
            head, rest = line.split("/*", 1)
            if "*/" in rest:
                line = head + rest.split("*/", 1)[1]
            else:
                line = head
                in_block_comment = True
                break
        for marker in ("#", "//"):
            if marker in line:
                line = line.split(marker, 1)[0]
        out.append(line)
    return "\n".join(out)


def discover_backend_files(root: str | Path) -> list[Path]:
    """Every .tf file that declares a backend, anywhere in the tree.

    Terraform allows the block in any file in the module, so looking only for a root-level
    `backend.tf` meant a project that put it in `main.tf`, or in a subdirectory, was reported
    as having no backend evidence at all.
    """
    root = Path(root)
    found: list[Path] = []
    for path in sorted(root.rglob("*.tf")):
        if any(part in {".terraform", "corpus", ".git"} for part in path.parts):
            continue
        try:
            body = strip_comments(path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        if "backend" in body and "terraform" in body:
            found.append(path)
    return found


def scan_backend_config(text: str) -> list[Finding]:
    """Static assessment of a backend block."""
    text = strip_comments(text)
    attrs = parse_backend_block(text)
    if attrs is None:
        return [
            _f(
                "TG-P02",
                "no backend block found: Terraform would use local state",
                "Configure the encrypted S3 backend produced by terraform/bootstrap.",
            )
        ]

    findings: list[Finding] = []
    kind = attrs.get("backend_type")
    if kind == "local":
        findings.append(
            _f(
                "TG-P02",
                "local backend in use: state is written to the working directory",
                "Move to the remote S3 backend with encryption and locking.",
            )
        )
        return findings
    if kind != "s3":
        findings.append(
            _f(
                "TG-P02",
                f"unrecognised backend type '{kind}'",
                "Use the S3 backend.",
                indeterminate=True,
            )
        )
        return findings

    if attrs.get("encrypt", "").lower() != "true":
        findings.append(
            _f(
                "TG-P03",
                "backend does not set encrypt = true",
                "Set encrypt = true on the S3 backend.",
            )
        )
    if attrs.get("use_lockfile", "").lower() != "true" and "dynamodb_table" not in attrs:
        findings.append(
            _f(
                "TG-P04",
                "no state locking configured",
                "Set use_lockfile = true (Terraform 1.11 or newer).",
            )
        )
    if "dynamodb_table" in attrs:
        findings.append(
            _f(
                "TG-P04",
                "state locking uses the deprecated dynamodb_table argument",
                "Replace with use_lockfile = true; dynamodb_table will be removed by HashiCorp.",
            )
        )
    return findings


def scan_backend_live(
    bucket: str, *, session=None
) -> list[Finding]:  # pragma: no cover - needs AWS
    """Live assessment. Anything that cannot be determined is reported as such."""
    try:
        import boto3
    except ImportError:
        return [
            _f(
                "TG-P03",
                "boto3 unavailable; live backend checks skipped",
                "Install boto3.",
                address=bucket,
                indeterminate=True,
            )
        ]
    s3 = (session or boto3).client("s3")
    findings: list[Finding] = []

    def _check(call, control, detail, remediation, ok):
        try:
            resp = call()
        except Exception as exc:
            findings.append(
                _f(
                    control,
                    f"could not determine: {exc.__class__.__name__}",
                    remediation,
                    address=bucket,
                    indeterminate=True,
                )
            )
            return
        if not ok(resp):
            findings.append(_f(control, detail, remediation, address=bucket))

    _check(
        lambda: s3.get_bucket_encryption(Bucket=bucket),
        "TG-P03",
        "state bucket has no default encryption",
        "Enable SSE on the state bucket.",
        lambda r: bool(r.get("ServerSideEncryptionConfiguration")),
    )
    _check(
        lambda: s3.get_bucket_versioning(Bucket=bucket),
        "TG-P05",
        "state bucket versioning is not enabled",
        "Enable versioning to allow state recovery.",
        lambda r: r.get("Status") == "Enabled",
    )
    _check(
        lambda: s3.get_public_access_block(Bucket=bucket),
        "TG-P02",
        "state bucket does not block all public access",
        "Enable all four public-access blocks.",
        lambda r: all((r.get("PublicAccessBlockConfiguration") or {}).values()),
    )
    return findings
