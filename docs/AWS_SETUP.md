# Manual AWS setup

These steps cannot be automated from this repository. Do them once, in order.

## 1. Dedicated account

Use a research or sandbox account that holds nothing else. Do not reuse a personal account
with real resources in it.

## 2. Region lock

Pick one region and never deviate: `eu-west-2` throughout this repo. Multi-region drift
adds nothing to the research and doubles the cleanup surface.

## 3. Budget alarms before anything is deployed

Billing → Budgets → Create budget → Cost budget:

- Threshold 1: **USD 5**, alert at 100% actual.
- Threshold 2: **USD 15**, alert at 100% actual and 100% forecast.

Send both to the email you actually read. Do this **before** `terraform apply`.

## 4. Local credentials

Create an IAM user for local development with programmatic access only, and attach a policy
scoped to the services this project uses: S3, EC2 security groups, IAM (read + the baseline
role/policy), CloudTrail, DynamoDB (lock table), STS.

```bash
aws configure --profile terraguard
export AWS_PROFILE=terraguard   # PowerShell: $env:AWS_PROFILE="terraguard"
aws sts get-caller-identity
```

Never place these keys in the repository, in a workflow, or in a `.tfvars` file.

## 5. GitHub OIDC role (needed in Phase 9, not now)

Create an IAM OIDC identity provider for `token.actions.githubusercontent.com`, then a role
whose trust policy restricts `sub` to this repository and, ideally, one branch:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    },
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/terraguard-ai:ref:refs/heads/main"
    }
  }
}
```

Grant it read-only permissions. The CI workflow only ever needs to *refresh* state, never to
apply. This satisfies TG-P09 (short-lived credentials) which the insecure workflow fixture
deliberately violates.

## 6. Cost discipline

- No EC2 instances. The baseline deploys a security group, not a server.
- CloudTrail: one trail, single region, log file validation on.
- `terraform destroy` in `terraform/baseline` at the end of every working session, or run
  `scenarios/restore_baseline.py` if you are mid-experiment.
- Full teardown at the end of the project: baseline first, then bootstrap.
