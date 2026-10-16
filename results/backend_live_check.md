# Live backend check (T041)

16 October 2026, `terraguard.backend_scanner.scan_backend_live`, IAM user `terraguard-dev`,
us-east-1. Read-only calls: get_bucket_encryption, get_bucket_versioning,
get_public_access_block.

| Bucket | Role | Findings |
|---|---|---:|
| `terraguard-state-jp-7f3a21` | Terraform state backend | 0 |
| `terraguard-test-3fbe6b36` | baseline drift target | 0 |
| `terraguard-does-not-exist-0000` | negative control | 3 |

Both real buckets are encrypted, versioned and block public access, so no finding is the
correct result. The negative control shows that a clean result is not a check that failed
quietly: a bucket that cannot be read returns `could not determine: NoSuchBucket` for TG-P03,
TG-P05 and TG-P02, which the policy engine treats as indeterminate, never compliant.
