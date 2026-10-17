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

## Cost (T108)

The account is shared with another course project, and the `Project` tag that every TerraGuard
resource carried was never activated as a cost allocation tag. Cost Explorer therefore cannot
filter spend by project, and activating the tag now would not apply to costs already incurred.
A TerraGuard-only bill is not available.

What can be shown is that no further TerraGuard cost is possible: every resource above was
confirmed absent after teardown. The project used S3 and CloudTrail plus free services (IAM,
security groups, the first two budgets), and both budget alarms at 5 and 15 USD were in place
from bootstrap to teardown. Activating the project tag on the first day, or using a dedicated
account, would have made the exact figure available (R31).
