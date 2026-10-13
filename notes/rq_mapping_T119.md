# T119 - Research questions mapped to evidence

Each question, the dataset fields that answer it, the metric, and where the number comes from.
If a row cannot be filled from a committed artefact, it is not an answer.

## RQ1 - Can Terraform state exposure and infrastructure drift be detected reliably?

| | |
|---|---|
| Fields | `detection_match`, `expected_control`, `findings_count`, `evidence_source` |
| Metric | share of runs raising the control the manifest named |
| Result | 684 of 684 |
| Artefact | `datasets/observations.csv`, `results/data_quality.json` |
| Caveat | Internal consistency over generated scenarios. The end-to-end proof that a real credential is caught and blocked is `scripts/demo_leak_prevention.py`, 8 of 8 checks. |

The drift half rests on plan JSON documents written to specification rather than captured from
a live refresh. Until the AWS runs in the runbook are recorded, RQ1 is answered for repository,
workflow and backend evidence, and provisionally for drift.

## RQ2 - Can severity be prioritised better than a deterministic rule?

| | |
|---|---|
| Fields | `deterministic_severity`, the 16 context features, group by `scenario_id` |
| Metric | macro F1 and recall on the high/critical class, grouped cross-validation |
| Result | LR 0.6699, RF 0.5482 |
| Artefact | `results/model_comparison.md`, `results/training_report.json` |
| Caveat | **Not answerable as the study stands.** |

The labels come from `severity_rules.py`, which is also the deterministic comparator, so the
comparator scores 1.0 by construction. No ranking between rules and models is possible while
one contestant supplies the labels. The independent review of a sample (T112) and the
disagreement log (T113) are what would close this. Recorded as risk R20.

## RQ3 - Does policy assessment avoid false assurance?

| | |
|---|---|
| Fields | `actual_policy_status`, `controls_assessed`, `assessment_coverage`, `policy_match` |
| Metric | policy status agreement, and coverage reported with every compliance figure |
| Result | 684 of 684; coverage 0.0 to 0.875 |
| Artefact | `datasets/observations.csv`, `notes/traceability_T118.md` |
| Caveat | One control, TG-P05, has no run behind it because it needs live AWS evidence. |

The `indeterminate` outcome is the substance of this question. A control that applies but could
not be assessed never reads as compliant, and the CLI warns rather than passing silently.

## RQ4 - Can this run as a CI gate without leaking what it finds?

| | |
|---|---|
| Fields | exit codes, report contents, `processing_time_ms` |
| Metric | gate behaviour by band; absence of any secret value in output |
| Result | critical and high exit 1, medium warns, low exits 0; 0 secret values in any report |
| Artefact | `.github/workflows/terraguard.yml`, `scripts/demo_leak_prevention.py`, `tests/test_cli.py` |
| Caveat | Timing is local only. The local versus CI comparison needs recorded runs (T102). |
