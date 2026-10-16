"""Find secrets already sitting in AWS, where the repository scanner cannot see them (TG-P14).

The rest of TerraGuard stops a credential reaching GitHub. This covers the places a Terraform
workflow tends to leave one inside the account instead:

* **S3 objects** - a state file or saved plan copied into an ordinary bucket, outside the one
  backend that is meant to hold it, or a text object such as a config or env file with a key
  or a password in it;
* **SSM Parameter Store** - a parameter whose name says it holds a password, token or key but
  whose type is `String`, so anyone with `ssm:GetParameter` reads it in clear.

Everything is read-only. Object bodies are read in memory, matched, and discarded; a finding
carries the key name and a length, never the value, exactly as the repository scanner does.
SSM is judged from metadata alone (`DescribeParameters`), so no parameter value is ever read.
Where a call is refused or a bucket cannot be listed, the finding says so and is marked
indeterminate, because a check that could not run is not a check that passed.
"""

from __future__ import annotations

import re

from .models import EvidenceSource, Finding, NormalisedEvent
from .repository_scanner import SECRET_PATTERNS, SENSITIVE_KEY_RE, find_sensitive_key_values

__all__ = ["scan_s3_objects", "scan_ssm_parameters", "scan_aws_storage"]

CONTROL = "TG-P14"

_STATE_OR_PLAN = re.compile(
    r"(\.tfstate(\.\d+)?(\.backup)?|\.tfplan|(^|/)(tfplan|plan)(\.json)?)$", re.IGNORECASE
)
# Compressed, binary and log formats are skipped. CloudTrail delivers gzip, and reading every
# access log line would turn a security check into a cost.
_SKIP_SUFFIX = re.compile(
    r"\.(gz|zip|tar|tgz|bz2|7z|png|jpe?g|gif|pdf|parquet|avro|orc|bin|exe|dll|so|whl)$",
    re.IGNORECASE,
)
MAX_OBJECT_BYTES = 1_000_000
MAX_OBJECTS_PER_BUCKET = 500


def _finding(
    suffix: str,
    address: str,
    resource_type: str,
    detail: str,
    remediation: str,
    *,
    indeterminate: bool = False,
) -> Finding:
    return Finding(
        finding_id=f"aws:{address}:{suffix}",
        evidence_source=EvidenceSource.AWS_API,
        resource_type=resource_type,
        resource_address=address,
        normalised_event=NormalisedEvent.SENSITIVE_DATA_EXPOSURE,
        control_id=CONTROL,
        detail=detail,
        remediation=remediation,
        raw={"indeterminate": indeterminate},
    )


def _looks_like_log(bucket: str, key: str) -> bool:
    return "logs" in bucket.lower() or key.startswith(("AWSLogs/", "access-logs/"))


def scan_s3_objects(s3, bucket: str, *, state_bucket: str | None = None) -> list[Finding]:
    """State and plan files outside the backend, and secrets inside small text objects."""
    findings: list[Finding] = []
    try:
        pages = s3.get_paginator("list_objects_v2").paginate(
            Bucket=bucket, PaginationConfig={"MaxItems": MAX_OBJECTS_PER_BUCKET}
        )
        objects = [obj for page in pages for obj in page.get("Contents", [])]
    except Exception as exc:  # noqa: BLE001 - every refusal is reported, none is fatal
        return [
            _finding(
                "list",
                bucket,
                "aws_s3_bucket",
                f"could not determine: {exc.__class__.__name__} listing {bucket}",
                "Grant s3:ListBucket on this bucket to the scanning role.",
                indeterminate=True,
            )
        ]

    for obj in objects:
        key = obj["Key"]
        address = f"s3://{bucket}/{key}"
        if _STATE_OR_PLAN.search(key):
            if bucket != state_bucket:
                findings.append(
                    _finding(
                        "state",
                        address,
                        "aws_s3_object",
                        "Terraform state or plan stored outside the state backend",
                        "Delete it, rotate every secret it held, and keep state only in "
                        "the encrypted backend bucket.",
                    )
                )
            continue
        if bucket == state_bucket:
            continue  # the backend is meant to hold state; TG-P02 to TG-P05 cover it
        if _SKIP_SUFFIX.search(key) or _looks_like_log(bucket, key):
            continue
        if obj.get("Size", 0) > MAX_OBJECT_BYTES:
            continue
        try:
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except Exception as exc:  # noqa: BLE001
            findings.append(
                _finding(
                    "read",
                    address,
                    "aws_s3_object",
                    f"could not determine: {exc.__class__.__name__} reading the object",
                    "Grant s3:GetObject on this bucket to the scanning role.",
                    indeterminate=True,
                )
            )
            continue
        text = body.decode("utf-8", errors="ignore")
        del body
        label = next((name for pattern, name in SECRET_PATTERNS if pattern.search(text)), None)
        if label:
            findings.append(
                _finding(
                    "secret",
                    address,
                    "aws_s3_object",
                    f"{label} found in an S3 object",
                    "Rotate the credential, delete the object and any older versions.",
                )
            )
            continue
        for name, size in find_sensitive_key_values(text):
            findings.append(
                _finding(
                    name,
                    address,
                    "aws_s3_object",
                    f"value under sensitive key '{name}' ({size}) in an S3 object",
                    "Rotate the credential and move it to Secrets Manager or a "
                    "SecureString parameter.",
                )
            )
        del text
    return findings


def scan_ssm_parameters(ssm) -> list[Finding]:
    """Parameters named like secrets but stored as plain String or StringList."""
    try:
        pages = ssm.get_paginator("describe_parameters").paginate()
        parameters = [p for page in pages for p in page.get("Parameters", [])]
    except Exception as exc:  # noqa: BLE001
        return [
            _finding(
                "describe",
                "ssm:parameters",
                "aws_ssm_parameter",
                f"could not determine: {exc.__class__.__name__} describing parameters",
                "Grant ssm:DescribeParameters to the scanning role. It returns "
                "metadata only, never parameter values.",
                indeterminate=True,
            )
        ]
    findings: list[Finding] = []
    for p in parameters:
        name = p.get("Name", "")
        if p.get("Type") != "SecureString" and SENSITIVE_KEY_RE.search(name.rsplit("/", 1)[-1]):
            findings.append(
                _finding(
                    "plaintext",
                    f"ssm:{name}",
                    "aws_ssm_parameter",
                    f"parameter named like a secret is stored as {p.get('Type')}, not "
                    "SecureString",
                    "Recreate it as SecureString with a KMS key, then rotate the value.",
                )
            )
    return findings


def scan_aws_storage(
    session, buckets: list[str], *, state_bucket: str | None = None, include_ssm: bool = True
) -> list[Finding]:
    s3 = session.client("s3")
    findings: list[Finding] = []
    for bucket in dict.fromkeys(b for b in buckets if b):
        findings += scan_s3_objects(s3, bucket, state_bucket=state_bucket)
    if include_ssm:
        findings += scan_ssm_parameters(session.client("ssm"))
    return findings
