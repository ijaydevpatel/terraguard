# Rules against published severities (T112, part one)

159 of 711 findings have a matching published control. On those, the rules agree with the published severity on 105 (66.0%), Cohen's kappa 0.2392.

| Finding type | Control | External | Published band | Rule band | Findings | Agrees |
|---|---|---|---|---|---:|---|
| TG-P08 repository_file | TG-P08 | Token-Permissions | high_or_critical | medium | 54 | **no** |
| TG-P10 aws_s3_bucket_public_access_block | TG-P10 | S3.8 | high_or_critical | high_or_critical | 18 | yes |
| TG-P10 aws_security_group | TG-P10 | EC2.13 | high_or_critical | high_or_critical | 3 | yes |
| TG-P10 aws_vpc_security_group_ingress_rule | TG-P10 | EC2.13 | high_or_critical | high_or_critical | 33 | yes |
| TG-P11 aws_iam_policy | TG-P11 | IAM.1 | high_or_critical | high_or_critical | 3 | yes |
| TG-P11 aws_iam_role_policy (partial match) | TG-P11 | IAM.1 | high_or_critical | high_or_critical | 15 | yes |
| TG-P12 aws_cloudtrail | TG-P12 | CloudTrail.3 | high_or_critical | high_or_critical | 18 | yes |
| TG-P12 aws_s3_bucket_logging | TG-P12 | S3.9 | medium | medium | 15 | yes |

## Models against the same published severities

Out-of-fold predictions under grouped cross-validation, 20 split seeds. The models were
trained on rule labels, so this asks only whether either lands nearer the published
rating than the rules it learned from.

| Predictor | Agreement with published band |
|---|---|
| Rules | 66.0% |
| logistic_regression | 55.5% (range 43.4% to 73.6%) |
| random_forest | 67.5% (range 56.6% to 90.6%) |

552 findings have no published equivalent:

- TG-P01 insecure_state_handling on repository_file: 156
- TG-P07 insecure_state_handling on repository_file: 81
- TG-P06 sensitive_data_exposure on repository_file: 78
- TG-P04 insecure_state_handling on repository_file: 36
- TG-P02 insecure_state_handling on repository_file: 33
- - non_security_operational_drift on aws_s3_bucket: 24
- - non_security_operational_drift on aws_vpc_security_group_ingress_rule: 21
- TG-P09 privilege_expansion on repository_file: 18
- TG-P13 out_of_band_deletion on aws_s3_bucket: 18
- - non_security_operational_drift on aws_iam_role: 18
- - non_security_operational_drift on aws_cloudtrail: 18
- TG-P03 insecure_state_handling on repository_file: 15
- TG-P12 encryption_disabled on aws_s3_bucket_server_side_encryption_configuration: 15
- - non_security_operational_drift on aws_s3_bucket_logging: 15
- - non_security_operational_drift on aws_security_group: 3
- TG-P13 out_of_band_deletion on aws_s3_bucket_public_access_block: 3

Sources and the reasoning for every match are in `datasets/external_severity_map.csv`.
Critical and High map to high_or_critical, Medium to medium, Low to non_security_or_low.
