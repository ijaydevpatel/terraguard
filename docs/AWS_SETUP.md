# Manual AWS setup

These steps cannot be automated from this repository. Do them once, in order.

## 1. Dedicated account

Use a research or sandbox account that holds nothing else. Do not reuse a personal account
with real resources in it.

### What a new account actually gets (accounts created after 15 July 2025)

The old 12-month Free Tier no longer applies to new accounts. The current structure is:

- Choose the **Free plan** at sign-up. It provides **USD 100 in credits**, rising to **USD 200**
  by completing five onboarding activities worth USD 20 each.
- One of those five activities is **creating a cost budget in AWS Budgets** - which
  `terraform/bootstrap/budgets.tf` does on the first apply, so that USD 20 comes for free here.
- The Free plan runs for **6 months**, or until the credits are spent, after which the account
  is closed automatically. Credits themselves expire 12 months after account creation.
- Over 30 services remain "always free" with permanent monthly limits.

This project's footprint is a security group, three small S3 buckets, one IAM role and policy,
and one CloudTrail trail. State locking is S3-native, so there is no lock table. No EC2, no RDS. That sits inside the
always-free limits for the most part and costs a few dollars at most against the credits, so a
6-month window comfortably covers a project ending in November.

One consequence worth noting: on the Free plan an exhausted credit balance closes the account
rather than generating a bill. Keep the budget alarms and destroy resources between sessions.

## 2. Region lock

Pick one region and never deviate: **`ap-southeast-2` (Sydney)** throughout this repo.

AWS opened **`ap-southeast-6` (Asia Pacific, New Zealand)** in Auckland on 2 September 2025,
so Sydney is no longer the closest region. Sydney is still the deliberate choice here: it has
the broader service catalogue and far more documentation and community material, which matters
more for a research prototype than the small latency saving. Recorded as a decision rather
than left as an unexamined default.

Multi-region drift adds nothing to the research and doubles the cleanup surface. AWS Budgets is
the one exception - it is a global service and is created in `us-east-1` through an aliased
provider.

## 3. Budget alarms

Both alarms are defined in Terraform (`terraform/bootstrap/budgets.tf`) and created by the
first `apply`, so there is nothing to click:

- **USD 5** - alert at 100% actual.
- **USD 15** - alert at 100% actual and 100% forecast.

Set `budget_alert_email` in `terraform/bootstrap/terraform.tfvars` to an address you read.
Budgets is a global service, so these are created in `us-east-1` via an aliased provider even
though everything else lives in `ap-southeast-2`.

## 4. Local credentials

Create an IAM user for local development with programmatic access only and attach the policy
in `docs/iam/local_dev_policy.json`. It is scoped to exactly the services this project needs -
S3, EC2 security groups, IAM, CloudTrail, Budgets, STS - and carries an explicit
`Deny` on the expensive ones (`ec2:RunInstances`, RDS, EKS, ElastiCache, SageMaker, Redshift)
so a mistake cannot become a bill.

```bash
aws configure --profile terraguard
export AWS_PROFILE=terraguard   # PowerShell: $env:AWS_PROFILE="terraguard"
aws sts get-caller-identity
```

Never place these keys in the repository, in a workflow, or in a `.tfvars` file.

## 5. GitHub OIDC role

Also defined in Terraform (`terraform/bootstrap/github_oidc.tf`) and gated behind a variable.
Set `github_repository = "owner/repo"` in `terraform.tfvars` and re-apply; leave it empty and
the provider and role are simply not created.

The trust policy restricts `sub` to one repository and the `main` branch, and the attached
policy is read-only plus state locking - the pipeline runs `plan -refresh-only`, never `apply`.
This satisfies TG-P09, which the `insecure_workflow` fixture deliberately violates.

The role ARN comes out as the `github_ci_role_arn` output; paste it into the workflow's
`configure-aws-credentials` step.

## 6. Automated setup

Once the profile exists, `scripts/aws_bootstrap.ps1` runs the whole sequence: bootstrap apply,
backend block generation, baseline apply, a zero-drift confirmation via
`plan -refresh-only -detailed-exitcode`, and the first evidence bundle.

## 7. Cost discipline

- No EC2 instances. The baseline deploys a security group, not a server.
- CloudTrail: one trail, single region, log file validation on.
- `terraform destroy` in `terraform/baseline` at the end of every working session, or run
  `scenarios/restore_baseline.py` if you are mid-experiment.
- Full teardown at the end of the project: baseline first, then bootstrap.
