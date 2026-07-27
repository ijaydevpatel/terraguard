# TerraGuard-AI

A local-first Python CLI that analyses Terraform-generated evidence, detects infrastructure
drift and unsafe state-file handling, assesses a small catalogue of technical security controls,
and **ranks** the resulting findings with two supervised models. Distributed with a GitHub
Action for CI/CD demonstration.

> **Design rule:** detection is deterministic, ranking is learned. No model output decides
> whether drift exists or whether a control was violated.

## Status

| Phase | Scope | State |
|---|---|---|
| P0 | Repo hardening, environment, package skeleton | **done** |
| P1 | Terraform baseline, evidence collector, redactor, fixtures | **done** (AWS apply pending) |
| P2 | Plan parser, drift extraction, normalisation | next |
| P3–P10 | Scanners, controls, dataset, models, reporting, CI | see `PROJECT_PLAN.md` |

## Install

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements-dev.txt
pip install -e .
pre-commit install
pytest -q
```

## Use it without AWS

Everything downstream of evidence collection runs offline from a sanitised plan JSON.
This is deliberate: no module may require credentials.

```bash
terraguard collect --plan-json tests/fixtures/plan_sg_drift.json --output evidence/
```

## Use it against real infrastructure

```bash
# 1. once: create the encrypted state backend
cd terraform/bootstrap
cp example.tfvars terraform.tfvars   # set a globally unique bucket name
terraform init && terraform apply
terraform output backend_block       # paste into ../baseline/backend.tf

# 2. deploy the secure baseline
cd ../baseline
terraform init && terraform apply

# 3. collect refresh-only drift evidence
cd ../..
terraguard collect --terraform-dir terraform/baseline --output evidence/ --scenario-id SG-001
```

See `docs/AWS_SETUP.md` for the account, budget-alarm and OIDC steps, which are manual.

## Repository layout

```
terraguard/          package: collector, parser, scanners, policy engine, features, models, reporting
policies/            TG-P01..TG-P12 control catalogue (YAML)
terraform/bootstrap/ encrypted S3 + DynamoDB state backend
terraform/baseline/  the secure baseline: 1 SG, 2 buckets + log bucket, 1 role + policy, 1 trail
terraform/fixtures/  synthetic clean / insecure_backend / insecure_workflow / exposed_state
scenarios/           out-of-band injection scripts (Phase 5)
datasets/            scenario catalogue, manifests, observations, features, data dictionary
scripts/             pre-commit guard and helper scripts
tests/               pytest suite and sanitised plan-JSON fixtures
notes/decisions.md   running design log; the source of the methodology chapter
```

## Safety rules this repo enforces

1. `.gitignore` plus a custom pre-commit hook refuse `*.tfstate`, `*.tfstate.backup`, saved
   plans and state-derived JSON, and any file containing an AWS access key id.
2. `terraguard.redactor` runs **on write**. The binary plan and raw plan JSON live only inside
   a temp directory and are deleted in a `finally` block; only the sanitised copy is kept.
3. Every credential-shaped value in this repository is the synthetic marker
   `TERRAGUARD_TEST_SECRET_nnn`. Account id `000000000000` does not exist.
4. Datasets published with this project are sanitised. Values are replaced by
   `[REDACTED]:len=n:sha256:...` references so findings stay correlatable but not recoverable.

## Limitations

Single region (ap-southeast-2), single AWS account, AWS only, small controlled dataset, no automatic
remediation, no dashboard. The severity models are exploratory: the transparent rule baseline
in `severity_rules.py` is reported alongside them precisely because it may win.
