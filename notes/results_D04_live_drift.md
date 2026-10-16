# D04b - Live drift detection against AWS

16 October 2026, account in us-east-1, IAM user `terraguard-dev`, Terraform 1.16.5.

Every other detection figure in this project comes from configurations written to disk. These
seven rows come from changes made to real AWS resources through the API, picked up by
`terraform plan -refresh-only`, and scored against manifests written before any run.

## What was run

`scripts/run_aws_experiment.py`, one scenario at a time, three passes over the six scenarios
that produce drift and one over S3-001. For each run: confirm the baseline is
clean, inject one change with boto3, capture the refresh-only plan as JSON, record the
observation through the same harness as the synthetic corpus, restore, confirm clean, delete
the plan JSON. The per-scenario logs are in `build/aws_log_<scenario>.txt` and every
injection and restore is in `datasets/injection_runs.jsonl`.

## Results

| Scenario | Change made in AWS | Control raised | Band | Gate | Runs matched |
|---|---|---|---|---|---|
| SG-001 | SSH rule widened from 10.0.0.0/8 to 0.0.0.0/0 | TG-P10 | high/critical | fail (1) | 3 / 3 |
| S3-001 | default encryption config deleted | none | - | pass (0) | no drift existed |
| S3-002 | public access block disabled | TG-P10 | high/critical | fail (1) | 3 / 3, first after correction |
| IAM-001 | wildcard action added to the baseline policy | TG-P11 | high/critical | fail (1) | 3 / 3 |
| LOG-001 | CloudTrail logging stopped | TG-P12 | high/critical | fail (1) | 3 / 3 |
| TAG-001 | Owner tag added to the test bucket | none | non-security | pass (0) | 3 / 3 |
| DEL-001 | access-log bucket deleted | TG-P13 | high/critical | fail (1) | 3 / 3, first after correction |

19 live observations. All 18 runs that produced drift were detected and matched their
manifest, all 15 security runs failed the gate, and the 3 tag runs, the negative control,
passed it. Every restore returned the baseline to zero drift before the next run started.
IAM-001's third attempt first failed at injection, before changing anything: a managed policy
keeps at most five versions and every injection adds one. The script now prunes old
non-default versions, and the rerun is the row counted here.

## Two manifest errors, found only because the run was live

S3-002 and DEL-001 were first scored as misses. In both, the tool was right and the manifest
was wrong. S3-002's manifest named TG-P02, the remote-backend control, while its own expected
event `restricted_to_public_network_access` maps to TG-P10. DEL-001 named TG-P12 while its
expected event `out_of_band_deletion` maps to TG-P13, the deletion control.

Both manifests were corrected on 16 Oct with the original value kept in
`expected_control_original` and a dated note, and the two rows were rescored. A test now
checks every drift manifest against the event-to-control table, so the same inconsistency
fails the build. No synthetic run could have caught this, because the synthetic corpus uses
its own generated templates and never read these seven manifests.

## S3-001 is not a detection miss

Since January 2023, S3 applies SSE-S3 (AES256) to every bucket. Deleting a bucket's
encryption configuration no longer leaves it unencrypted; it falls back to AES256. The
baseline already specifies AES256, so after the injection the real bucket matched the
configuration exactly and there was no drift to detect. The tool reported none, which was
correct.

The scenario as designed cannot be reproduced on current AWS. It stays in the dataset with a
note rather than being deleted, and it is excluded from the live detection count above. A
weakening that still exists would be moving a bucket from SSE-KMS to SSE-S3, which needs a
KMS key in the baseline; that is recorded as R28 rather than built after the freeze.

## Two infrastructure problems the run exposed

**The restore reported drift that was not there.** After SG-001 the restore apply reverted
the rule in AWS, but the parent `aws_security_group` keeps a computed copy of its ingress list
that had been refreshed before the revert. The next refresh-only plan showed 0.0.0.0/0 in
state against 10.0.0.0/8 in AWS, with AWS already correct. The restore now runs a refresh-only
apply to clear that copy, but only after a normal plan shows nothing to change and the API-side
check in `reset_aws_baseline.py` agrees, so it cannot write a real leftover into state.

**Terraform's exit code was wrong.** With `-detailed-exitcode`, Terraform 1.16.5 printed
"No changes" for a refresh-only plan and still exited 2. The restore now counts
`resource_drift` in the plan JSON instead, which is the same evidence the scanner reads.

## Noise on real plans

SG-001 produced four findings for one change: the managed rule and the parent group's computed
ingress list each reported the CIDR change and a description change. Both description findings
were classed non-security by rule 5 and the gate fired on the correct pair. On the synthetic
fixtures the same scenario produces one finding. The ratio is still something this project does
not measure across scenarios.

## What this does and does not establish

It establishes that the full chain works on real infrastructure for five security drift
classes plus a negative control: API change, refresh, correct control, correct band, correct
exit code, clean restore.

It does not establish a detection rate. Each scenario ran three times at most. Nineteen live
rows sit beside 684 synthetic ones, so D04's figures are still mostly synthetic and should be
read that way. The
gap described in R25, a resource added out of band with no state entry, is untouched by these
runs: SG-001 modifies a managed rule precisely because an added rule is invisible to a
refresh.
