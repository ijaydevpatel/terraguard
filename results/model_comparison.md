# Severity model comparison

711 findings from 57 scenario templates, grouped cross-validation with 3 splits.

## What is being predicted

The label is the severity band `severity_rules.py` assigns to a finding. The models
see context only - evidence source, resource type, path shape, run-level counts - and
never `control_id` or `normalised_event`, which are the two fields the rule ladder
switches on.

## Results

| Model | Macro F1 | Weighted F1 | Accuracy | Recall on high/critical |
|---|---:|---:|---:|---:|
| logistic_regression | 0.7016 | 0.7775 | 0.7722 | 0.8225 |
| random_forest | 0.811 | 0.8711 | 0.8776 | 0.9645 |

## The deterministic baseline is not in that table, on purpose

It scores 1.0 on every metric. That is arithmetic, not evidence: the labels are the
rules' own output, so the rules reproduce them exactly by construction. Listing that
row beside the models would read as the baseline winning, when the comparison cannot
rank them at all while the labels come from one of the contestants.

Making this a real comparison needs labels from outside the rules - the independent
review of a sample (T112) and the disagreement log (T113). Neither has happened, so no
rules-versus-models claim belongs in the results chapter yet.

## Leakage check (T076)

| Split | Rule inputs withheld | Rule inputs included |
|---|---:|---:|
| grouped by template | 0.7016 | 0.8449 |
| ungrouped (random) | 0.9166 | 1.0 |

Both defences do work. Grouping removes most of the inflation, because control ids are
confounded with scenario templates and a held-out template brings categories the model
has never seen. Withholding the rule inputs removes the rest: under grouping they still
lift the score, which is the model relearning the rule ladder rather than ranking.

## Class support

| Band | Findings | Independent templates |
|---|---:|---:|
| high_or_critical | 507 | 39 |
| medium | 105 | 11 |
| non_security_or_low | 99 | 10 |

## How much weight these numbers carry

The smallest class rests on 10 independent templates, and these figures come from one split seed.
`results/fold_stability.md` repeats the split under 20 seeds; quote that range rather
than the values above. Drift findings are mostly synthetic, with nineteen live AWS
observations, and the labels are one analyst's rubric applied consistently rather than
reviewed ground truth.
