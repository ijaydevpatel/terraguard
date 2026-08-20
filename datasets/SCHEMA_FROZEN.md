# Frozen schema — 11 August 2026

The pilot is done, so the observation schema is now fixed. Any change from here invalidates
the records already collected, because a row written under one schema cannot be compared
with a row written under another.

## What the pilot ran

Twelve observations across six offline templates, each run twice: ST-001, ST-002, WF-001,
BK-001, CLEAN-001, CLEAN-002. No AWS credentials were involved. The four drift templates
that need a deployed baseline were not part of the pilot and are still unrun.

## What it produced

| Measure | Result |
|---|---|
| Detection matched ground truth | 12 of 12 |
| Policy status matched ground truth | 12 of 12 |
| False alerts across four clean-control runs | 0 |
| Processing time | 125–366 ms, median 188 ms |
| Assessment coverage | 0.12 to 0.88 |

The coverage spread is the useful part. A repository-only scenario such as ST-001 gives the
engine evidence for one control out of eight, so seven come back indeterminate and coverage
drops to 0.12. That is the engine refusing to call a control compliant when it has not seen
the evidence. If coverage had stayed near 1.0 on those runs, something would have been wrong.

## Two things the pilot changed

The first draft of the harness read the manifest and passed the expected control into the
scanners. That would have let the answer leak into the detection step. The harness now loads
the manifest, sets it aside, runs collection and assessment blind, and only compares at the
point the row is written.

The clean-control runs originally reported coverage of 0.50 because the fixture had no
`backend.tf`. Adding one to `clean_002_workflow` lifted it to 0.88 and made the clean runs
comparable with the others.

## Frozen

- `datasets/data_dictionary.csv` — 21 fields, types, valid values, measurement rules
- `datasets/observations.csv` — one row per run
- `datasets/findings.csv` — one row per finding, joined on `run_id`
- The manifest format in `datasets/scenario_manifests/*.yaml`

`deterministic_severity` is present but empty. Phase 6 fills it. The column exists now so
that adding it later does not count as a schema change.

## Still open

Severity is recorded as a band rather than a class. The band comes from the manifest and is
a prediction, not a label. Final labels need the rubric in `docs/SEVERITY_RUBRIC.md`, and a
sample of them needs review by someone other than the author (T112). Until that happens the
severity column carries no weight.
