# Blind labels against the rules (T112 part two, T113)

Twenty findings, one per finding type, labelled by the project author on 17 Oct without the rule's band, the rule number or the control id, using a plain impact scale rather than the rule ladder (`scripts/make_label_sheet.py`).

Agreement with the rules: 15 of 20 (75%), Cohen's kappa 0.4949.

Where a published severity exists (8 items), the blind labels agree with it on 7.

| # | Finding type | Rule | Blind label | Published | Sure (1-3) |
|---:|---|---|---|---|---:|
| 1 | TG-P12 aws_s3_bucket_server_side_encryption_configuration | high_or_critical | medium (differs) | - | 2 |
| 2 | TG-P04 repository_file | medium | medium | - | 2 |
| 3 | TG-P02 repository_file | high_or_critical | high_or_critical | - | 2 |
| 4 | TG-P08 repository_file | medium | high_or_critical (differs) | high_or_critical | 2 |
| 5 | TG-P13 aws_s3_bucket_public_access_block | high_or_critical | medium (differs) | - | 2 |
| 6 | TG-P09 repository_file | high_or_critical | high_or_critical | - | 2 |
| 7 | TG-P06 repository_file | high_or_critical | high_or_critical | - | 2 |
| 8 | TG-P13 aws_s3_bucket | high_or_critical | high_or_critical | - | 2 |
| 9 | TG-P12 aws_s3_bucket_logging | medium | medium | medium | 2 |
| 10 | - aws_s3_bucket | non_security_or_low | non_security_or_low | - | 3 |
| 11 | TG-P01 repository_file | high_or_critical | high_or_critical | - | 3 |
| 12 | TG-P11 aws_iam_policy | high_or_critical | high_or_critical | high_or_critical | 3 |
| 13 | TG-P03 repository_file | high_or_critical | medium (differs) | - | 2 |
| 14 | TG-P10 aws_security_group | high_or_critical | high_or_critical | high_or_critical | 2 |
| 15 | TG-P11 aws_iam_role_policy | high_or_critical | high_or_critical | high_or_critical | 3 |
| 16 | TG-P12 aws_cloudtrail | high_or_critical | high_or_critical | high_or_critical | 3 |
| 17 | TG-P10 aws_vpc_security_group_ingress_rule | high_or_critical | high_or_critical | high_or_critical | 3 |
| 18 | TG-P10 aws_s3_bucket_public_access_block | high_or_critical | medium (differs) | high_or_critical | 2 |
| 19 | - aws_cloudtrail | non_security_or_low | non_security_or_low | - | 3 |
| 20 | TG-P07 repository_file | high_or_critical | high_or_critical | - | 1 |

## Disagreements and decisions (T113)

- **#1 TG-P12 on aws_s3_bucket_server_side_encryption_configuration**: rule high_or_critical, blind medium, published -. Labeller's reason: Data at rest is no longer encrypted. Someone still needs read access to the bucket before anything leaks.
- **#4 TG-P08 on repository_file**: rule medium, blind high_or_critical, published high_or_critical. Labeller's reason: Any step in the job, including third-party actions, gets a token that can push code and change the repo.
- **#5 TG-P13 on aws_s3_bucket_public_access_block**: rule high_or_critical, blind medium, published -. Labeller's reason: Whole public access block is gone, so a public ACL or policy would now take effect. Someone still has to add one.
- **#13 TG-P03 on repository_file**: rule high_or_critical, blind medium, published -. Labeller's reason: State in the S3 backend is stored unencrypted. Still needs access to the state bucket to read it.
- **#18 TG-P10 on aws_s3_bucket_public_access_block**: rule high_or_critical, blind medium, published high_or_critical. Labeller's reason: Public ACLs are no longer blocked on this bucket. Name says test, so maybe less data in it, but still worth checking.

The rules are not changed in response. A disagreement is recorded as evidence about the
rubric, not fixed after the fact, because tuning the rules to these twenty labels would
make them the training set for the next comparison.

Limitation: the labeller is the project author, so this is a weaker check than an
independent reviewer. It covers finding types no published standard rates.
