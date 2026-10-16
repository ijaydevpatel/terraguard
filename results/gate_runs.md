# Severity gate runs

Recorded 2026-10-16 11:21 UTC with
`terraguard scan <target> --no-history --include-optional --fail-on high`.

| Run | Target | Exit | Expected | Wall time (ms) |
|---|---|---:|---:|---:|
| clean pass | `terraform/fixtures/clean` | 0 | 0 | 811 |
| medium warn | `terraform/fixtures/bk_002_deprecated_lock` | 0 | 0 | 740 |
| critical fail | `terraform/fixtures/exposed_state` | 1 | 1 | 756 |

## clean pass

```
No findings.

warning: 1 control(s) could not be assessed - missing evidence is not the same 
as compliance
pass: nothing at or above high
```

## medium warn

```
SEVERITY  RULE  CONTROL  RESOURCE    DETAIL
-------------------------------------------
medium    4     TG-P04   backend.tf  state locking uses the deprecated dynamodb_table argument

1 finding(s): 0 high/critical, 1 medium, 0 non-security/low
assessment coverage 0.61-0.61 - a compliance figure quoted without this cannot be interpreted

warning: 1 control(s) could not be assessed - missing evidence is not the same 
as compliance
warning: 1 finding(s) below the high gate
pass: nothing at or above high
```

## critical fail

```
SEVERITY          RULE  CONTROL  RESOURCE                  DETAIL
-----------------------------------------------------------------
high_or_critical  1     TG-P01   terraform.tfstate.backup  Terraform state backup tracked in the repository
high_or_critical  1     TG-P01   terraform.tfstate         Terraform state file tracked in the repository
high_or_critical  1     TG-P07   tfplan.json               saved Terraform plan tracked in the repository

3 finding(s): 3 high/critical, 0 medium, 0 non-security/low
assessment coverage 0.15-0.15 - a compliance figure quoted without this cannot be interpreted

warning: 7 control(s) could not be assessed - missing evidence is not the same 
as compliance
FAIL: 3 finding(s) at or above high
```
