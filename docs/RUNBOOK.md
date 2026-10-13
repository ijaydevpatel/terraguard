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

## 5. Prove drift detection end to end

Inject one change outside Terraform, capture the plan, and let the tool find it.

```powershell
cd $HOME\Desktop\Terragaurd\terraguard-ai
python scenarios\inject_security_group_drift.py --port 22 --cidr 0.0.0.0/0
cd terraform\baseline
terraform plan -refresh-only -out=drift.tfplan
terraform show -json drift.tfplan > ..\..\evidence\drift.json
cd ..\..
python -m terraguard.cli analyse --plan-json evidence\drift.json --include-optional --fail-on high
```

Expect TG-P10, a high or critical band, and exit code 1. Check the exit code with:

```powershell
echo $LASTEXITCODE
```

Then put it back:

```powershell
python scenarios\restore_baseline.py
cd terraform\baseline; terraform plan -refresh-only; cd ..\..
```

The restore script refuses to run against anything that is not the research baseline, so it
cannot touch another account by accident.

The other injections follow the same pattern:

```powershell
python scenarios\inject_s3_encryption_drift.py
python scenarios\inject_s3_public_access.py
python scenarios\inject_iam_privilege_drift.py
python scenarios\inject_logging_drift.py
python scenarios\inject_tag_drift.py
python scenarios\delete_managed_resource.py
```

Run `restore_baseline.py` after each one.

---

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
