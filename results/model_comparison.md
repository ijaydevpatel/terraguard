# Severity model comparison

32 findings from 11 scenario templates, grouped cross-validation with 3 splits.

## What is being predicted

The label is the severity band `severity_rules.py` assigns to a finding. The models
see context only - evidence source, resource type, path shape, run-level counts - and
never `control_id` or `normalised_event`, which are the two fields the rule ladder
switches on.

## Results

| Model | Macro F1 | Weighted F1 | Accuracy | Recall on high/critical |
|---|---:|---:|---:|---:|
| logistic_regression | 0.5687 | 0.5387 | 0.5625 | 0.2857 |
| random_forest | 0.7714 | 0.7357 | 0.75 | 0.4286 |

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
| grouped by template | 0.5687 | 0.5687 |
| ungrouped (random) | 0.7186 | 0.9259 |

Grouping, not the feature exclusion, is what defeats the leak: control ids are
confounded with scenario templates, so a held-out template brings categories the model
has never seen. The gap in the left-hand column is the price of the honest split.

## Class support

| Band | Findings | Independent templates |
|---|---:|---:|
| high_or_critical | 14 | 4 |
| medium | 10 | 5 |
| non_security_or_low | 8 | 3 |

## How much weight these numbers carry

A small study: the smallest class rests on three independent templates, so differences
of a few points between models are noise. The drift half of the dataset is empty, so
none of this covers infrastructure drift, and the labels are one analyst's rubric
applied consistently rather than reviewed ground truth.
