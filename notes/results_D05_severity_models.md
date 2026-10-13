# D05 - Severity model comparison

678 findings from 51 scenario templates, grouped cross-validation
with 3 splits, `random_state=20261014`.

## What the models predict

The label is the severity band `severity_rules.py` assigns to a finding. The models are given
context only: evidence source, resource type, attribute path shape, whether the change was
remote, whether sensitive data was involved, run level counts. They never see `control_id` or
`normalised_event`, which are the two fields the rule ladder switches on.

## Results

| Model | Macro F1 | Weighted F1 | Accuracy | Recall on high/critical |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.6699 | 0.7629 | 0.7611 | 0.821 |
| Random Forest | 0.5482 | 0.7123 | 0.7301 | 0.8704 |

Logistic Regression is ahead on macro F1 and Random Forest is ahead on recall for the class
that matters most. That is a real trade and not a tie: the forest catches more severe findings
(0.8704 against 0.821) while being noisier on the two
smaller classes, which macro F1 punishes because it weights every class equally.

This also reverses the result from the small dataset, where the forest led on macro F1. With
11 templates that figure rested on a handful of findings. The reversal is a good argument for
not quoting single point estimates from small corpora, including the earlier ones in this
project.

## The deterministic baseline is still not in that table

It scores 1.0 on every metric because the labels are its own output. That is arithmetic, not
evidence. While the labels come from one of the contestants the comparison cannot rank them,
and no rules versus models claim belongs in the results chapter. Breaking the circularity
needs the independent review of a sample (T112) and the disagreement log (T113).

## Leakage check

Logistic Regression, same data, four ways:

| Split | Rule inputs withheld | Rule inputs included |
|---|---:|---:|
| Grouped by template | 0.6699 | 0.859 |
| Ungrouped (random) | 0.8854 | 1.0 |

On the small corpus the rule inputs made no difference under grouping, and the conclusion
recorded at the time was that grouping alone defeated the leak. **That conclusion was an
artefact of having too few templates.** With 51 templates, many of which share a
control id, the rule inputs now lift the grouped score from
0.6699 to 0.859,
and an ungrouped split with them reaches 1.0 - a
perfect score that measures nothing except the model rediscovering the lookup table.

Both defences are therefore doing work, and the earlier write-up understated the feature
exclusion. Grouping alone is worth
0.2155
macro F1 of inflation avoided.

## Class support

| Band | Findings | Independent templates |
|---|---:|---:|
| high_or_critical | 486 | 34 |
| medium | 105 | 11 |
| non_security_or_low | 87 | 8 |

The high/critical class is much the largest, at 486
findings from 34 templates. That imbalance is a
property of the subject rather than of the sampling: most ways of mishandling Terraform state
expose it outright. Both models use balanced class weights, and macro F1 is reported precisely
because accuracy would flatter a model that simply guessed the majority class.

## What the model leans on

Top Random Forest importances:

- `detail_length` 0.2945
- `resource_type=repository_file` 0.1132
- `evidence_source=terraform_plan_json` 0.1013
- `persistence_across_runs` 0.09
- `evidence_source=repository` 0.07
- `path_mentions_permission` 0.0577

`detail_length` being the single strongest feature is a problem worth stating plainly. It is
close to a fingerprint of which scanner wrote the message rather than anything about the
danger of the finding. A model leaning on it will generalise badly to a catalogue it was not
trained on. Dropping run level and message shape features and re-running is the obvious next
test, and it is cheap.

## Weight these numbers can carry

The corpus is synthetic. Every configuration was written by a generator and scanned by the
real pipeline, so the findings are genuine detections of real misconfigurations, but the
population they are drawn from is one I designed. It is not a sample of what people actually
commit.

The AWS drift runs are the part that is not synthetic, and they are recorded separately.
