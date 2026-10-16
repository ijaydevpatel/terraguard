# Secrets left in AWS (TG-P14, extension)

16 October 2026, IAM user `terraguard-dev`, us-east-1. Added after the feature freeze as a
bug-fix-sized extension, outside the 13-control experiment: TG-P14 is loaded only by
`terraguard scan-aws`, so no dataset row, coverage figure or model result changes because of it.

## What it checks

| Where | Finding | How it reads |
|---|---|---|
| S3, any bucket except the state backend | a `.tfstate`, `.tfplan` or `plan.json` object | object names only |
| S3 text objects up to 1 MB | an AWS key, private key or GitHub token shape, or a value under a sensitive key name | body read in memory, matched, discarded; key name and length reported |
| SSM Parameter Store | a parameter named like a secret stored as `String` instead of `SecureString` | `DescribeParameters` metadata; no value is read |

Compressed objects, CloudTrail and access-log prefixes are skipped. A bucket or service that
cannot be read is reported as indeterminate, never as clean.

## Live results

| Run | Target | Result |
|---|---|---|
| Real buckets | state backend, test bucket, access-log bucket | 0 findings, exit 0 |
| SSM | Parameter Store | indeterminate: the IAM user lacks `ssm:DescribeParameters` |
| Positive control | test bucket with a planted placeholder key file and a fake state file | both named, gate exit 1, key never printed |
| After clean-up | test bucket | every object version removed, rescan exit 0 |

`scripts/demo_aws_secret_scan.py` passed 7 of 7 checks. The planted key is AWS's published
documentation placeholder, so no real credential was involved at any point.

## Limits

Secrets Manager, Lambda environment variables, EC2 user data and ECS task definitions are not
read. The SSM check needs `ssm:DescribeParameters` added to the IAM policy
(`docs/iam/local_dev_policy.json` now carries it). Each scenario ran once; this shows the
check works, not how often it misses.
