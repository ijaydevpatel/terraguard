# TerraGuard-AI

A local-first Python CLI that analyses Terraform-generated evidence, detects infrastructure
drift and unsafe state-file handling, assesses a small catalogue of technical security controls,
and **ranks** the resulting findings with two supervised models. Distributed with a GitHub
Action for CI/CD demonstration.

> **Design rule:** detection is deterministic, ranking is learned. No model output decides
> whether drift exists or whether a control was violated.

## Status

Feature freeze was Fri 16 Oct 2026. The build is complete: scanners, policy engine, severity
models, reporting, the CI gate and the AWS drift experiment all run. What is still open is
listed under Limitations, and the full task list lives in `TerraGuard_Build_Tracker.xlsx`.

## Install

Python 3.11 or newer. The package install was checked from a fresh clone in a clean 3.12
virtual environment with no AWS credentials on the machine.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -e ".[cli]"          # the scanner and report only
pip install -e ".[cli,scenarios]" # adds boto3 for the AWS injection scripts
terraguard --version
```

For development (tests, ruff, black, pre-commit):

```bash
pip install -r requirements-dev.txt
pip install -e .
pre-commit install
pytest -q
```

## Use it without AWS

Everything downstream of evidence collection runs offline from a plan JSON. No module needs
credentials to do this.

```bash
terraguard analyse --plan-json tests/fixtures/plan_sg_drift.json --include-optional --fail-on high
terraguard analyse --plan-json tests/fixtures/plan_sg_drift.json --format json --output out/report.json
terraguard scan . --include-optional --fail-on high
terraguard evaluate
terraguard train
```

| Command | What it does |
|---|---|
| `scan` | repository, workflow and backend checks on a directory, including git history |
| `analyse` | drift and policy assessment from a `terraform show -json` plan |
| `collect` | runs Terraform and keeps only the sanitised evidence |
| `train` | fits Logistic Regression and Random Forest with grouped cross-validation |
| `evaluate` | scores detection and policy outcomes over the dataset |
| `report` | renders the dataset as a terminal, JSON or CSV report |

Exit codes: `0` nothing at or above the `--fail-on` level, `1` findings at or above it, `2` a
usage error. Medium findings below the gate print a warning, and so does any control that
could not be assessed, because missing evidence is not compliance.

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

The seven drift scenarios run from one command, which injects each change through the AWS API,
captures the refresh-only plan, records the observation, restores the baseline and deletes the
plan JSON. `docs/RUNBOOK.md` has the full sequence.

```bash
python scripts/reset_aws_baseline.py --profile default
python scripts/run_aws_experiment.py --profile default --dry-run
python scripts/run_aws_experiment.py --profile default
```

## Repository layout

```
terraguard/          package: collector, parser, scanners, policy engine, features, models, reporting
policies/            TG-P01..TG-P12 control catalogue (YAML)
terraform/bootstrap/ encrypted S3 state backend with native locking, budgets, OIDC role
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

Single region (us-east-1), single AWS account, AWS only, controlled dataset, no automatic
remediation, no dashboard.

- Refresh-only plans cannot see a resource added out of band, such as a new security group
  rule with no state entry. Any tool that reads `terraform plan` shares this gap (R25).
  `scripts/reset_aws_baseline.py` checks for it through the API instead.
- The severity labels come from `severity_rules.py`, which is also the baseline the models are
  compared against. Until a sample is labelled independently (T112), the models can be compared
  with each other but not with the rules.
- Most observations come from the synthetic corpus. The live AWS runs cover seven scenarios,
  19 observations in all.

## License

MIT - see [LICENSE](LICENSE).

Note that the synthetic fixtures under `terraform/fixtures/` are intentionally insecure
configurations used as test oracles. They are not examples to copy.
