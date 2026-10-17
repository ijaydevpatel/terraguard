# AWS teardown (T107)

17 October 2026, us-east-1. `terraform destroy` on the baseline, then on the bootstrap.

| Stack | Destroyed | Note |
|---|---:|---|
| baseline, first attempt | 17 of 19 | stopped at the security group and IAM role: the policy lacked `ec2:DescribeNetworkInterfaces` and `iam:ListInstanceProfilesForRole`, both read-only, added the same day |
| baseline, second attempt | 2 of 2 | security group and `terraguard-baseline-role` |
| bootstrap, after emptying the state bucket | 10 of 10 | state bucket and its settings, two budgets, the GitHub OIDC provider, the CI role and its policy |

## Confirmed from the AWS side afterwards

Each resource was looked up by name with the API, so the result does not rest on Terraform's
own report.

| Resource | Result |
|---|---|
| Buckets `terraguard-state-*`, `terraguard-test-*`, `terraguard-logs-*`, `terraguard-trail-*` | not found |
| Security group `sg-0154f42cdfb4f0cff` | not found |
| Roles `terraguard-baseline-role`, `terraguard-ci` | not found |
| Policy `terraguard-baseline-policy` | not found |
| Trail `terraguard-trail` | not found |
| Budgets `terraguard-monthly-5usd`, `terraguard-monthly-15usd` | not found |
| GitHub OIDC provider | not found |

Nothing created by this project remains in the account. The IAM user `terraguard-dev` and its
access key were created by hand in the console and are not managed by Terraform; removing
them is a separate console step.
