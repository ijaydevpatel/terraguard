# Runbook

Every command you need, in order.

**These are PowerShell commands.** `$HOME` is PowerShell syntax and does nothing in Command
Prompt, so either open PowerShell or substitute `%USERPROFILE%` and use `cd /d` throughout.
Mixing the two is the quickest way to get "The system cannot find the path specified".

| | PowerShell | Command Prompt |
|---|---|---|
| Home directory | `$HOME` | `%USERPROFILE%` |
| Change drive and directory | `cd` | `cd /d` |
| Last exit code | `$LASTEXITCODE` | `%ERRORLEVEL%` |

The project folder is spelled `Terragaurd` on disk. That is not a typo in this document.

Nothing here needs me. Credentials never leave your machine and are never pasted into a
chat, which is why the AWS steps are yours to run rather than mine.

---

## 1. Install Terraform for all users

Run this in an **Administrator** PowerShell. The machine scope is what makes it available to
every user rather than just your profile.

```powershell
winget install --id HashiCorp.Terraform --scope machine --accept-source-agreements --accept-package-agreements
```

Close and reopen PowerShell, then check:

```powershell
terraform version
```

You want 1.11 or newer. The project uses S3-native state locking, which arrived in 1.10, and
the old `dynamodb_table` argument is deprecated.

If `winget` is unavailable, Chocolatey in an Administrator prompt does the same job:

```powershell
choco install terraform -y
```

---

## 1b. Install the project

Do this before anything that runs `terraguard`.

```powershell
cd $HOME\Desktop\Terragaurd\terraguard-ai
python -m pip install -e ".[cli,scenarios]"
```

`pydantic` and `PyYAML` are required and come with the base install. The two extras are
deliberate: `cli` adds `rich` for formatted tables, and the CLI falls back to plain text
without it; `scenarios` adds `boto3`, which only the AWS injection scripts need. The scanner
itself never calls AWS, which is how the entire offline corpus was produced on a machine with
no SDK installed.

Check it:

```powershell
terraguard --version
python -m terraguard.cli scan . --fail-on high
```

---

## 2. Point the AWS CLI at your new account

```powershell
winget install --id Amazon.AWSCLI --scope machine
aws configure
```

Enter the access key and secret for the IAM user you created, region `us-east-1`, output
`json`. Confirm it works and note the account id:

```powershell
aws sts get-caller-identity
```

Guardrails before you create anything that costs money:

```powershell
aws budgets describe-budgets --account-id (aws sts get-caller-identity --query Account --output text)
```

---

## 3. Create the state backend

```powershell
cd $HOME\Desktop\Terragaurd\terraguard-ai\terraform\bootstrap
copy example.tfvars terraform.tfvars
notepad terraform.tfvars     # set a globally unique bucket name and your alert email
terraform init
terraform plan -out=bootstrap.tfplan
terraform apply bootstrap.tfplan
terraform output
```

This creates the encrypted, versioned state bucket with public access blocked, the budget
alarms at $5 and $15, and the GitHub OIDC role. Note the bucket name from `terraform output`.

`prevent_destroy` is deliberately off on this bucket so the environment can be torn down
cleanly at the end. That is a stated deviation from production guidance, recorded in the
limitations section.

---

## 4. Deploy the baseline

```powershell
cd ..\baseline
terraform init     # answer yes when it offers to migrate state to the S3 backend
terraform plan -out=baseline.tfplan
terraform apply baseline.tfplan
```

Confirm it is clean. A fresh apply should show no drift at all:

```powershell
terraform plan -refresh-only
```

---

## 4b. Clear any leftover drift

Do this before the first experiment run, and any time a run halts part way.

```powershell
cd $HOME\Desktop\Terragaurd\terraguard-ai
python scripts\reset_aws_baseline.py --profile default
python scripts\reset_aws_baseline.py --profile default --apply
cd terraform\baseline;  terraform apply;  cd ..\..
```

The first command only reports. The second reverts what it found. The `terraform apply` settles
anything Terraform manages itself.

This step exists because `terraform plan -refresh-only` can report a clean baseline while the
security group is open to the world. Both statements can be true at once, for the reason in
section 5.

---

## 5. Run every drift scenario

One command. It confirms the baseline is clean, then for each scenario injects the change
through the AWS API, captures a refresh-only plan, records the observation through the normal
harness, restores the baseline, confirms it is clean again, and deletes the plan JSON.

```powershell
cd $HOME\Desktop\Terragaurd\terraguard-ai
python scripts\run_aws_experiment.py --profile default --dry-run
```

The dry run locates every target and changes nothing. If it finds them all, run it properly:

```powershell
python scripts\run_aws_experiment.py --profile default
```

Seven scenarios: security group opened, bucket encryption removed, public access block
disabled, IAM widened to a wildcard, CloudTrail stopped, a tag edited, and a managed resource
deleted. Expect `gate exit 1` on the six security scenarios and `0` on the tag change, which is
the negative control.

It stops at the first scenario that does not come back clean, and leaves the environment
restored. A single scenario can be run on its own:

```powershell
python scripts\run_aws_experiment.py --profile default --only SG-001
```

Everything it does is written to `build\aws_experiment_log.txt`.

### What refresh-only cannot see

The baseline manages ingress as individual `aws_vpc_security_group_ingress_rule` resources, one
Terraform resource per rule. A rule *added* through the AWS API has no state entry, so a refresh
has nothing to reconcile it against and reports no changes. The group is wide open and the plan
is clean.

That is not a defect in this tool. Any scanner that reads refresh output inherits it, because
Terraform is doing what it says: reconciling the resources it manages. It is recorded as R25 and
reported in the limitations rather than worked around quietly.

The consequence for the experiment is that SG-001 now *modifies the managed rule* - rewriting
the baseline SSH source from `10.0.0.0/8` to `0.0.0.0/0` - rather than adding a new one. Same
posture regression, same severity, and in state, so refresh sees it and `terraform apply`
restores it.

The old behaviour is kept deliberately, to demonstrate the gap instead of tripping over it:

```powershell
python scenarios\inject_security_group_drift.py --run-id blindspot-1 --profile default --unmanaged
cd terraform\baseline;  terraform plan -refresh-only;  cd ..\..
```

That plan will report no changes. Clean up with `scripts\reset_aws_baseline.py --apply`, because
`terraform apply` will not: it does not know the rule exists.

### Two safety properties

The plan JSON holds every attribute of every refreshed
resource in cleartext, so it is deleted after each scenario whether that scenario succeeded or
failed. And `restore_baseline.py` refuses to run unless the caller is an IAM user and the state
it is about to apply to carries `Project=TerraGuard-AI` and `Environment=test`. It runs
`terraform apply -auto-approve`, which is the most destructive command in this repository, and
until today it did that without checking what it was pointed at.

## 6. Record the runs into the dataset

```powershell
python scenarios\run_experiment.py SG-001 --plan-json evidence\drift.json
```

Use the scenario id that matches the injection. `datasets\scenario_catalogue.csv` lists them.
Each run appends one row to `datasets\observations.csv` and its findings to
`datasets\findings.csv`.

---

## 7. Tear down when you are finished

```powershell
cd terraform\baseline;  terraform destroy
cd ..\bootstrap;        terraform destroy
cd ..\..
aws ce get-cost-and-usage --time-period Start=2026-10-01,End=2026-10-31 --granularity MONTHLY --metrics UnblendedCost
```

---

## Offline commands, no AWS needed

These work right now and are the quickest way to see the tool behave.

```powershell
cd $HOME\Desktop\Terragaurd\terraguard-ai

# Scan a directory that has state committed. Exits 1.
python -m terraguard.cli scan corpus\GEN-STATE-ROOT\00 --include-optional --fail-on high
echo $LASTEXITCODE

# Scan a correctly configured one. Exits 0.
python -m terraguard.cli scan corpus\GEN-BK-SECURE\00 --fail-on high
echo $LASTEXITCODE

# Assess drift from a plan JSON.
python -m terraguard.cli analyse --plan-json corpus\GEN-DRIFT-SGOPEN\00\plan.json --include-optional

# Machine readable, safe to pipe.
python -m terraguard.cli scan corpus\GEN-SECRET-AWSKEY\00 --format json

# Scan this repository itself.
python -m terraguard.cli scan . --fail-on high

# Rebuild the whole corpus and the dataset.
python scenarios\generate_corpus.py --variations 15

# Detection and policy figures over the dataset.
python -m terraguard.cli evaluate

# Fit the severity models and write the comparison.
python -m terraguard.cli train

# Everything CI runs, in CI's order.
python scripts\preflight.py
```

---

## What the exit codes mean

| Code | Meaning |
|---:|---|
| 0 | nothing at or above the gate |
| 1 | at least one finding at or above the gate |
| 2 | usage error, such as a path that does not exist |

A control that could not be assessed prints a warning and does not pass silently. Missing
evidence is not compliance, and the tool will not pretend otherwise.
