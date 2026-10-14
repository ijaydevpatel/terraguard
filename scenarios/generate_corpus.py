"""Build the synthetic scenario corpus and run every variation through the real scanners.

Two things make this a dataset rather than a pile of rows.

**Families are the unit that matters.** Evaluation groups folds by scenario template, so the
ceiling on what can be learned is the number of independent families, not the row count.
Replaying one family fifty times gives fifty rows and one group. So the corpus is built the
other way round: many distinct families, each with a handful of parameter variations.

**Nothing is invented.** Each variation is written to disk as a real configuration and then
scanned by the same `repository_scanner`, `workflow_scanner`, `backend_scanner` and
`policy_engine` the tool uses in anger. The rows record what the scanners actually found. A
manifest naming the expected control is written before the scan, never after.

The corpus itself lives in `corpus/`, which is gitignored: it is regenerable output, and some
of it deliberately contains credential-shaped strings that must never be committed. The
generator is committed and seeded, so anyone can rebuild it byte for byte.

    python scenarios/generate_corpus.py --variations 15
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from terraguard.backend_scanner import scan_backend_config  # noqa: E402
from terraguard.drift_extractor import extract_from_plan  # noqa: E402
from terraguard.drift_normaliser import normalise  # noqa: E402
from terraguard.models import UTC, EvidenceSource, PolicyStatus  # noqa: E402
from terraguard.policy_engine import assess, assessment_coverage, load_controls  # noqa: E402
from terraguard.repository_scanner import (  # noqa: E402
    scan_file_contents,
    scan_paths,
    scan_temp_artefacts,
)
from terraguard.severity_rules import classify_all  # noqa: E402
from terraguard.workflow_scanner import scan_workflows  # noqa: E402

CORPUS = ROOT / "corpus"
MANIFESTS = ROOT / "datasets" / "scenario_manifests"
OBSERVATIONS = ROOT / "datasets" / "observations.csv"
FINDINGS = ROOT / "datasets" / "findings.csv"
CATALOGUE = ROOT / "datasets" / "scenario_catalogue.csv"

OBS_FIELDS = [
    "run_id",
    "scenario_id",
    "scenario_group",
    "tier",
    "run_started",
    "evidence_source",
    "resource_type",
    "fixture",
    "expected_drift",
    "detected_drift",
    "expected_control",
    "expected_policy_status",
    "actual_policy_status",
    "expected_severity_band",
    "deterministic_severity",
    "findings_count",
    "controls_assessed",
    "assessment_coverage",
    "detection_match",
    "policy_match",
    "processing_time_ms",
    "notes",
]
FIND_FIELDS = [
    "run_id",
    "scenario_id",
    "finding_id",
    "is_remote_drift",
    "evidence_source",
    "control_id",
    "normalised_event",
    "resource_address",
    "detail",
]

# Synthetic markers only. Assembled at runtime so no literal credential shape is ever written
# into a committed file; the corpus that receives them is gitignored as well.
FAKE_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
FAKE_GH_TOKEN = "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"
    + "x" * 40
    + "\n-----END RSA PRIVATE KEY-----"
)
MARKER = "TERRAGUARD" + "_TEST_SECRET_"

SECURE_BACKEND = """terraform {{
  backend "s3" {{
    bucket       = "{bucket}"
    key          = "{key}/terraform.tfstate"
    region       = "{region}"
    encrypt      = true
    use_lockfile = true
  }}
}}
"""


def _state_body(seed: int) -> str:
    """A state-shaped document. Values are synthetic markers, never real secrets."""
    return json.dumps(
        {
            "version": 4,
            "terraform_version": "1.11.0",
            "serial": seed,
            "resources": [
                {
                    "type": "aws_db_instance",
                    "name": "app",
                    "instances": [{"attributes": {"password": f"{MARKER}{seed:03d}"}}],
                }
            ],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------------------
# Families. Each entry is one independent group in the cross-validation.
# ---------------------------------------------------------------------------------------


def repo_family(name: str, filename: str, control: str, band: str, note: str) -> dict:
    def build(d: Path, p: dict) -> None:
        target = d / filename.format(**p)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_state_body(p["seed"]), encoding="utf-8")
        (d / "backend.tf").write_text(SECURE_BACKEND.format(**p), encoding="utf-8")

    return dict(
        id=name,
        group="state_security",
        build=build,
        control=control,
        band=band,
        event="insecure_state_handling",
        resource="repository_file",
        drift=False,
        status="non_compliant",
        note=note,
    )


def secret_family(name: str, filename: str, payload, note: str) -> dict:
    def build(d: Path, p: dict) -> None:
        body = payload(p) if callable(payload) else payload
        (d / filename).write_text(body, encoding="utf-8")
        (d / "backend.tf").write_text(SECURE_BACKEND.format(**p), encoding="utf-8")

    return dict(
        id=name,
        group="sensitive_data",
        build=build,
        control="TG-P06",
        band="high_or_critical",
        event="sensitive_data_exposure",
        resource="repository_file",
        drift=False,
        status="non_compliant",
        note=note,
    )


def backend_family(
    name: str, template: str, control: str, band: str, note: str, status: str = "non_compliant"
) -> dict:
    def build(d: Path, p: dict) -> None:
        (d / "backend.tf").write_text(template.format(**p), encoding="utf-8")

    return dict(
        id=name,
        group="state_security",
        build=build,
        control=control,
        band=band,
        event="insecure_state_handling",
        resource="terraform_backend",
        drift=False,
        status=status,
        note=note,
    )


def workflow_family(
    name: str,
    template: str,
    control: str,
    band: str,
    note: str,
    status: str = "non_compliant",
    event: str = "privilege_expansion",
) -> dict:
    def build(d: Path, p: dict) -> None:
        wf = d / ".github" / "workflows"
        wf.mkdir(parents=True, exist_ok=True)
        (wf / "plan.yml").write_text(template.format(**p), encoding="utf-8")
        (d / "backend.tf").write_text(SECURE_BACKEND.format(**p), encoding="utf-8")

    return dict(
        id=name,
        group="cicd_security",
        build=build,
        control=control,
        band=band,
        event=event,
        resource="github_workflow",
        drift=False,
        status=status,
        note=note,
    )


def drift_family(
    name: str,
    maker,
    control: str,
    band: str,
    event: str,
    attribute: str,
    note: str,
    status: str = "non_compliant",
) -> dict:
    return dict(
        id=name,
        group="infrastructure_drift",
        plan=maker,
        control=control,
        band=band,
        event=event,
        resource="aws_resource",
        drift=True,
        status=status,
        attribute=attribute,
        note=note,
    )


LOCAL_BACKEND = (
    'terraform {{\n  backend "local" {{\n    path = "{key}/terraform.tfstate"\n  }}\n}}\n'
)
NO_ENCRYPT = """terraform {{
  backend "s3" {{
    bucket       = "{bucket}"
    key          = "{key}/terraform.tfstate"
    region       = "{region}"
    use_lockfile = true
  }}
}}
"""
NO_LOCK = """terraform {{
  backend "s3" {{
    bucket  = "{bucket}"
    key     = "{key}/terraform.tfstate"
    region  = "{region}"
    encrypt = true
  }}
}}
"""
DEPRECATED_LOCK = """terraform {{
  backend "s3" {{
    bucket         = "{bucket}"
    key            = "{key}/terraform.tfstate"
    region         = "{region}"
    encrypt        = true
    dynamodb_table = "{bucket}-locks"
  }}
}}
"""
NO_BACKEND = 'terraform {{\n  required_version = ">= 1.11"\n}}\n'

WF_HEAD = "name: {key}\non: [pull_request]\n"
WF_ARTEFACT = (
    WF_HEAD
    + """permissions:
  contents: read
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: terraform plan -out=tfplan
      - uses: actions/upload-artifact@v4
        with:
          name: tfplan
          path: tfplan
"""
)
WF_CACHE = (
    WF_HEAD
    + """permissions:
  contents: read
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: .terraform/terraform.tfstate
          key: tf-{seed}
      - run: terraform plan
"""
)
WF_ECHO = (
    WF_HEAD
    + """permissions:
  contents: read
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - run: terraform show -json tfplan > tfplan.json
      - run: cat tfplan.json
"""
)
WF_WRITE_ALL = (
    WF_HEAD
    + "permissions: write-all\njobs:\n  plan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: terraform plan\n"
)
WF_READ_ALL = (
    WF_HEAD
    + "permissions: read-all\njobs:\n  plan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: terraform plan\n"
)
WF_NO_PERM = (
    WF_HEAD
    + "jobs:\n  plan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: terraform plan\n"
)
WF_LONG_LIVED = (
    WF_HEAD
    + """permissions:
  contents: read
jobs:
  plan:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: ${{{{ secrets.AWS_ACCESS_KEY_ID }}}}
      AWS_SECRET_ACCESS_KEY: ${{{{ secrets.AWS_SECRET_ACCESS_KEY }}}}
    steps:
      - run: terraform plan
"""
)
WF_SECURE = (
    WF_HEAD
    + """permissions:
  contents: read
  id-token: write
jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::000000000000:role/ci
          aws-region: {region}
      - run: terraform plan
"""
)


def _drift(resource: str, name: str, before: dict, after: dict, actions=("update",)) -> dict:
    return {
        "format_version": "1.2",
        "terraform_version": "1.11.0",
        "resource_drift": [
            {
                "address": f"{resource}.{name}",
                "mode": "managed",
                "type": resource,
                "name": name,
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": list(actions),
                    "before": before,
                    "after": after,
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
    }


FAMILIES: list[dict] = [
    # --- committed state and plan artefacts (TG-P01 / TG-P07) ---
    repo_family(
        "GEN-STATE-ROOT",
        "terraform.tfstate",
        "TG-P01",
        "high_or_critical",
        "state file committed at the repository root",
    ),
    repo_family(
        "GEN-STATE-NESTED",
        "{key}/terraform.tfstate",
        "TG-P01",
        "high_or_critical",
        "state file committed inside an environment directory",
    ),
    repo_family(
        "GEN-STATE-BACKUP",
        "terraform.tfstate.backup",
        "TG-P01",
        "high_or_critical",
        "state backup committed",
    ),
    repo_family(
        "GEN-STATE-NUMBERED",
        "terraform.tfstate.{seed}.backup",
        "TG-P01",
        "high_or_critical",
        "numbered state backup committed",
    ),
    repo_family(
        "GEN-PLAN-BINARY", "tfplan", "TG-P07", "high_or_critical", "saved binary plan committed"
    ),
    repo_family(
        "GEN-PLAN-JSON",
        "tfplan.json",
        "TG-P07",
        "high_or_critical",
        "state-derived plan JSON committed",
    ),
    repo_family(
        "GEN-PLAN-NAMED",
        "plan.json",
        "TG-P07",
        "high_or_critical",
        "plan JSON committed under the generic name",
    ),
    repo_family(
        "GEN-TEMP-TMP",
        "terraform.tfstate.tmp",
        "TG-P01",
        "high_or_critical",
        "leftover state working file",
    ),
    repo_family(
        "GEN-TEMP-ORIG",
        "terraform.tfstate.orig",
        "TG-P01",
        "high_or_critical",
        "leftover state .orig file",
    ),
    repo_family(
        "GEN-TEMP-CACHED",
        ".terraform/terraform.tfstate",
        "TG-P01",
        "high_or_critical",
        "state cached under .terraform",
    ),
    repo_family(
        "GEN-TEMP-CRASH",
        "crash.log",
        "TG-P01",
        "high_or_critical",
        "Terraform crash log, which can contain state values",
    ),
    repo_family(
        "GEN-TEMP-PLANOUT",
        "plan.out",
        "TG-P01",
        "high_or_critical",
        "plan output captured to a file",
    ),
    # --- secrets inside tracked files (TG-P06) ---
    secret_family(
        "GEN-SECRET-AWSKEY",
        "providers.tf",
        lambda p: f'provider "aws" {{\n  access_key = "{FAKE_AWS_KEY}"\n  region = "{p["region"]}"\n}}\n',
        "AWS access key id in a tracked file",
    ),
    secret_family(
        "GEN-SECRET-PEM",
        "deploy_key.tf",
        lambda p: f'resource "tls_private_key" "k" {{\n  private_key_pem = <<EOT\n{FAKE_PEM}\nEOT\n}}\n',
        "PEM private key block in a tracked file",
    ),
    secret_family(
        "GEN-SECRET-GHTOKEN",
        "ci.tf",
        lambda p: f'variable "gh_token" {{\n  default = "{FAKE_GH_TOKEN}"\n}}\n',
        "GitHub token in a tracked file",
    ),
    # The fixture marker is on the scanner's suppression list by design, so a family using
    # it as the value could never be detected. This one needs a value with no recognisable
    # shape that is also not a known placeholder - which is the whole point of the rule.
    secret_family(
        "GEN-SECRET-KEYNAME",
        "db.tf",
        lambda p: f'resource "aws_db_instance" "a" {{\n  password = "pw-{p["seed"]:03d}-aXbYcZ"\n}}\n',
        "value under a sensitive key name, no recognisable shape",
    ),
    # --- backend configuration ---
    backend_family(
        "GEN-BK-LOCAL",
        LOCAL_BACKEND,
        "TG-P02",
        "high_or_critical",
        "local backend, state never leaves the workstation",
    ),
    backend_family(
        "GEN-BK-NONE", NO_BACKEND, "TG-P02", "high_or_critical", "no backend block at all"
    ),
    backend_family(
        "GEN-BK-NOENCRYPT",
        NO_ENCRYPT,
        "TG-P03",
        "high_or_critical",
        "remote backend without encryption at rest",
    ),
    backend_family("GEN-BK-NOLOCK", NO_LOCK, "TG-P04", "medium", "no state locking configured"),
    backend_family(
        "GEN-BK-DYNAMODB", DEPRECATED_LOCK, "TG-P04", "medium", "deprecated dynamodb_table locking"
    ),
    backend_family(
        "GEN-BK-SECURE",
        SECURE_BACKEND,
        "",
        "non_security_or_low",
        "correctly configured backend, negative control",
        status="compliant",
    ),
    # --- CI/CD workflows ---
    workflow_family(
        "GEN-WF-ARTEFACT",
        WF_ARTEFACT,
        "TG-P07",
        "high_or_critical",
        "saved plan uploaded as a workflow artefact",
        event="insecure_state_handling",
    ),
    workflow_family(
        "GEN-WF-CACHE",
        WF_CACHE,
        "TG-P07",
        "high_or_critical",
        "state path written to the Actions cache",
        event="insecure_state_handling",
    ),
    workflow_family(
        "GEN-WF-ECHO",
        WF_ECHO,
        "TG-P06",
        "high_or_critical",
        "plan contents echoed to the job log",
        event="sensitive_data_exposure",
    ),
    workflow_family(
        "GEN-WF-WRITEALL", WF_WRITE_ALL, "TG-P08", "medium", "token scope set to write-all"
    ),
    workflow_family(
        "GEN-WF-READALL", WF_READ_ALL, "TG-P08", "medium", "token scope set to read-all"
    ),
    workflow_family(
        "GEN-WF-NOPERM",
        WF_NO_PERM,
        "TG-P08",
        "medium",
        "no permissions block, token inherits the repository default",
    ),
    workflow_family(
        "GEN-WF-LONGLIVED", WF_LONG_LIVED, "TG-P09", "medium", "long-lived AWS keys instead of OIDC"
    ),
    workflow_family(
        "GEN-WF-SECURE",
        WF_SECURE,
        "",
        "non_security_or_low",
        "OIDC and least privilege, negative control",
        status="compliant",
    ),
    # --- infrastructure drift, from plan JSON ---
    drift_family(
        "GEN-DRIFT-SGOPEN",
        lambda p: _drift(
            "aws_vpc_security_group_ingress_rule",
            "ssh",
            {"cidr_ipv4": "10.0.0.0/8", "to_port": p["port"]},
            {"cidr_ipv4": "0.0.0.0/0", "to_port": p["port"]},
        ),
        "TG-P10",
        "high_or_critical",
        "public_network_access",
        "cidr_ipv4",
        "ingress opened to every address",
    ),
    drift_family(
        "GEN-DRIFT-SGOPEN6",
        lambda p: _drift(
            "aws_vpc_security_group_ingress_rule",
            "ssh6",
            {"cidr_ipv6": "fd00::/8", "to_port": p["port"]},
            {"cidr_ipv6": "::/0", "to_port": p["port"]},
        ),
        "TG-P10",
        "high_or_critical",
        "public_network_access",
        "cidr_ipv6",
        "IPv6 ingress opened to every address",
    ),
    drift_family(
        "GEN-DRIFT-ENCRYPT",
        lambda p: _drift(
            "aws_s3_bucket_server_side_encryption_configuration",
            "b",
            {"sse_algorithm": "aws:kms"},
            {"sse_algorithm": ""},
        ),
        "TG-P12",
        "high_or_critical",
        "encryption_disabled",
        "sse_algorithm",
        "bucket encryption removed",
    ),
    drift_family(
        "GEN-DRIFT-PUBLICACL",
        lambda p: _drift(
            "aws_s3_bucket_public_access_block",
            "b",
            {"block_public_acls": True},
            {"block_public_acls": False},
        ),
        "TG-P10",
        "high_or_critical",
        "public_network_access",
        "block_public_acls",
        "public access block disabled",
    ),
    drift_family(
        "GEN-DRIFT-IAMWILD",
        lambda p: _drift(
            "aws_iam_role_policy",
            "app",
            {"policy": '{"Action":"s3:GetObject"}'},
            {"policy": '{"Action":"*"}'},
        ),
        "TG-P11",
        "high_or_critical",
        "privilege_expansion",
        "policy",
        "IAM action widened to a wildcard",
    ),
    drift_family(
        "GEN-DRIFT-TRAILOFF",
        lambda p: _drift(
            "aws_cloudtrail", "main", {"enable_logging": True}, {"enable_logging": False}
        ),
        "TG-P12",
        "high_or_critical",
        "security_logging_disabled",
        "enable_logging",
        "the only audit trail stopped",
    ),
    drift_family(
        "GEN-DRIFT-DELETE",
        lambda p: _drift("aws_s3_bucket", "evidence", {"id": "b"}, None, actions=("delete",)),
        "TG-P13",
        "high_or_critical",
        "out_of_band_deletion",
        "id",
        "resource deleted outside Terraform",
    ),
    drift_family(
        "GEN-DRIFT-ACCESSLOG",
        lambda p: _drift(
            "aws_s3_bucket_logging",
            "b",
            {"target_bucket": "logs", "s3_access_logging": True},
            {"target_bucket": "", "s3_access_logging": False},
        ),
        "TG-P12",
        "medium",
        "security_logging_disabled",
        "s3_access_logging",
        "bucket access logging off while the trail still runs",
    ),
    drift_family(
        "GEN-DRIFT-TAGOWNER",
        lambda p: _drift(
            "aws_s3_bucket",
            "app",
            {"tags": {"Owner": "research"}},
            {"tags": {"Owner": f"team-{p['seed']}"}},
        ),
        "",
        "non_security_or_low",
        "non_security_operational_drift",
        "tags.Owner",
        "tag value changed, security position unchanged",
        status="compliant",
    ),
    drift_family(
        "GEN-DRIFT-TAGENV",
        lambda p: _drift(
            "aws_iam_role",
            "app",
            {"tags": {"environment": "test"}},
            {"tags": {"environment": f"test-{p['seed']}"}},
        ),
        "",
        "non_security_or_low",
        "non_security_operational_drift",
        "tags.environment",
        "environment label edited",
        status="compliant",
    ),
    drift_family(
        "GEN-DRIFT-DESC",
        lambda p: _drift(
            "aws_vpc_security_group_ingress_rule",
            "ssh",
            {"description": "admin CIDR only", "cidr_ipv4": "10.0.0.0/8"},
            {"description": "admin range", "cidr_ipv4": "10.0.0.0/8"},
        ),
        "",
        "non_security_or_low",
        "non_security_operational_drift",
        "description",
        "rule description reworded, CIDR unchanged",
        status="compliant",
    ),
    drift_family(
        "GEN-DRIFT-NAMETAG",
        lambda p: _drift(
            "aws_cloudtrail",
            "main",
            {"tags": {"Name": "trail"}},
            {"tags": {"Name": f"trail-{p['seed']}"}},
        ),
        "",
        "non_security_or_low",
        "non_security_operational_drift",
        "tags.Name",
        "name tag edited on the trail",
        status="compliant",
    ),
    drift_family(
        "GEN-DRIFT-REPAIR",
        lambda p: _drift(
            "aws_vpc_security_group_ingress_rule",
            "ssh",
            {"cidr_ipv4": "0.0.0.0/0"},
            {"cidr_ipv4": "10.0.0.0/8"},
        ),
        "",
        "non_security_or_low",
        "non_security_operational_drift",
        "cidr_ipv4",
        "public to restricted, a repair and not a finding",
        status="compliant",
    ),
]

REGIONS = ["ap-southeast-2", "ap-southeast-6", "us-east-1"]
ENVIRONMENTS = ["test", "staging", "production"]
PORTS = [22, 3389, 5432, 6379, 8080]


def variation_params(index: int, rng: random.Random) -> dict:
    return {
        "seed": index,
        "bucket": f"terraguard-state-{index:04d}",
        "key": f"{rng.choice(ENVIRONMENTS)}-{index:02d}",
        "region": rng.choice(REGIONS),
        "port": rng.choice(PORTS),
        "environment": rng.choice(ENVIRONMENTS),
    }


EMPTY = '""'


def write_manifest(family: dict, variations: int) -> None:
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    (MANIFESTS / f"{family['id']}.yaml").write_text(
        "# Ground truth, written before any run of this family.\n"
        f"scenario_id: {family['id']}\n"
        f"scenario_group: {family['group']}\n"
        "tier: core\n"
        f"resource_type: {family['resource']}\n"
        f"injected_change: {family['note']}\n"
        f"expected_drift: {str(family['drift']).lower()}\n"
        f"expected_attribute: {family.get('attribute', '')}\n"
        f"expected_policy_status: {family['status']}\n"
        f"expected_control: {family['control'] or EMPTY}\n"
        f"expected_normalised_event: {family['event']}\n"
        f"expected_severity_band: {family['band']}\n"
        f"planned_variations: {variations}\n"
        "needs_aws: false\n"
        "notes: >\n"
        "  Generated by scenarios/generate_corpus.py. Synthetic configuration, scanned by the\n"
        "  real detection pipeline. Not a substitute for the AWS drift runs.\n",
        encoding="utf-8",
    )


def scan_directory(d: Path):
    findings = []
    sources: set[EvidenceSource] = set()
    tracked = [str(p.relative_to(d)).replace("\\", "/") for p in d.rglob("*") if p.is_file()]
    if tracked:
        sources.add(EvidenceSource.REPOSITORY)
        findings += scan_paths(tracked, include_fixtures=True)
        findings += scan_temp_artefacts(tracked, include_fixtures=True)
        findings += scan_file_contents(d, tracked)
    if (d / ".github" / "workflows").exists():
        sources.add(EvidenceSource.WORKFLOW)
        findings += scan_workflows(d)
    backend = d / "backend.tf"
    if backend.exists():
        sources.add(EvidenceSource.BACKEND_CONFIG)
        findings += scan_backend_config(backend.read_text(encoding="utf-8"))
    return findings, sources


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variations", type=int, default=15)
    parser.add_argument("--seed", type=int, default=20261014)
    parser.add_argument("--keep", action="store_true", help="append instead of replacing")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CORPUS.mkdir(parents=True)

    # The drift and OIDC families exercise TG-P09 to TG-P12, which the catalogue marks
    # optional and excludes by default. Asking for them here is deliberate: the families
    # exist to test exactly those controls. It widens the coverage denominator, which the
    # recorded assessment_coverage reflects.
    controls = load_controls(ROOT / "policies", include_optional=True)
    observations: list[dict] = []
    finding_rows: list[dict] = []

    for family in FAMILIES:
        write_manifest(family, args.variations)
        for n in range(args.variations):
            params = variation_params(n, rng)
            run_id = f"{family['id']}-{uuid.uuid4().hex[:8]}"
            started = datetime.now(UTC)
            clock = time.perf_counter()

            if "plan" in family:
                plan = family["plan"](params)
                target = CORPUS / family["id"] / f"{n:02d}"
                target.mkdir(parents=True, exist_ok=True)
                (target / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")
                findings = normalise(extract_from_plan(plan), scenario_id=family["id"])
                sources = {EvidenceSource.TERRAFORM_PLAN_JSON}
                fixture = f"corpus/{family['id']}/{n:02d}/plan.json"
            else:
                target = CORPUS / family["id"] / f"{n:02d}"
                target.mkdir(parents=True, exist_ok=True)
                family["build"](target, params)
                findings, sources = scan_directory(target)
                fixture = f"corpus/{family['id']}/{n:02d}"

            results = assess(
                controls,
                findings,
                available_evidence=sources,
                observed_resource_types={f.resource_type for f in findings if f.resource_type}
                or None,
            )
            elapsed = (time.perf_counter() - clock) * 1000
            non_compliant = [r for r in results if r.status is PolicyStatus.NON_COMPLIANT]
            labels = classify_all(findings)
            rank = {"non_security_or_low": 0, "medium": 1, "high_or_critical": 2}
            worst = max((x.band for x in labels), key=lambda b: rank[b], default="")
            actual = "non_compliant" if non_compliant else "compliant"
            expected_control = family["control"]
            hit = (
                any(r.control_id == expected_control for r in non_compliant)
                if expected_control
                else not non_compliant
            )

            observations.append(
                {
                    "run_id": run_id,
                    "scenario_id": family["id"],
                    "scenario_group": family["group"],
                    "tier": "core",
                    "run_started": started.isoformat(timespec="seconds"),
                    "evidence_source": ",".join(sorted(s.value for s in sources)),
                    "resource_type": family["resource"],
                    "fixture": fixture,
                    "expected_drift": family["drift"],
                    "detected_drift": bool(findings),
                    "expected_control": expected_control,
                    "expected_policy_status": family["status"],
                    "actual_policy_status": actual,
                    "expected_severity_band": family["band"],
                    "deterministic_severity": worst,
                    "findings_count": len(findings),
                    "controls_assessed": len(results),
                    "assessment_coverage": round(assessment_coverage(results), 3),
                    "detection_match": hit,
                    "policy_match": actual == family["status"],
                    "processing_time_ms": round(elapsed, 2),
                    "notes": "" if hit else "expected control not raised - investigate",
                }
            )
            for f in findings:
                finding_rows.append(
                    {
                        "run_id": run_id,
                        "scenario_id": family["id"],
                        "finding_id": f.finding_id,
                        "is_remote_drift": bool((f.raw or {}).get("is_remote_drift")),
                        "evidence_source": f.evidence_source.value,
                        "control_id": f.control_id or "",
                        "normalised_event": f.normalised_event.value if f.normalised_event else "",
                        "resource_address": f.resource_address or "",
                        "detail": f.detail or "",
                    }
                )

    mode = "a" if args.keep else "w"
    with open(OBSERVATIONS, mode, encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OBS_FIELDS)
        if mode == "w":
            w.writeheader()
        w.writerows(observations)
    with open(FINDINGS, mode, encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIND_FIELDS)
        if mode == "w":
            w.writeheader()
        w.writerows(finding_rows)

    _sync_catalogue(args.variations)

    matched = sum(1 for o in observations if o["detection_match"])
    print(f"families          {len(FAMILIES)}")
    print(f"observations      {len(observations)}")
    print(f"findings          {len(finding_rows)}")
    print(f"detection match   {matched}/{len(observations)}")
    misses = [o["scenario_id"] for o in observations if not o["detection_match"]]
    if misses:
        print(f"MISSES            {sorted(set(misses))}")
    return 0


def _sync_catalogue(variations: int) -> None:
    rows = list(csv.DictReader(open(CATALOGUE, encoding="utf-8")))
    cols = list(rows[0].keys())
    rows = [r for r in rows if not r["scenario_id"].startswith("GEN-")]
    for family in FAMILIES:
        rows.append(
            {
                "scenario_id": family["id"],
                "scenario_group": family["group"],
                "resource_type": family["resource"],
                "injected_change": family["note"],
                "expected_drift": str(family["drift"]),
                "expected_attribute": family.get("attribute", ""),
                "expected_policy_status": family["status"],
                "expected_control": family["control"],
                "expected_event": family["event"],
                "expected_severity_band": family["band"],
                "evidence_source": "generated",
                "tier": "core",
                "needs_aws": "False",
                "planned_variations": variations,
            }
        )
    with open(CATALOGUE, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    raise SystemExit(main())
