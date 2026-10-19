# D05 - Severity model comparison

711 findings from 57 scenario templates, grouped cross-validation with 3 splits,
`random_state=20260916`. Regenerated on 16 Oct after the live AWS runs added 33 findings and
6 templates. The fold-stability section below matters more than any single figure here.

## What the models predict

The label is the severity band `severity_rules.py` assigns to a finding. The models are given
context only: evidence source, resource type, attribute path shape, whether the change was
remote, whether sensitive data was involved, run level counts. They never see `control_id` or
`normalised_event`, which are the two fields the rule ladder switches on.

## Results

| Model | Macro F1 | Weighted F1 | Accuracy | Recall on high/critical |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.7685 | 0.8272 | 0.8228 | 0.8521 |
| Random Forest | 0.8626 | 0.9046 | 0.9072 | 0.9704 |

Random Forest leads on every column at this split seed. These single-seed figures moved twice
on 16 Oct. After the first seven live rows, Logistic Regression went from 0.7789 to 0.7324 and
Random Forest from 0.8198 to 0.8874; after the repeat runs they went to 0.7016 and 0.811.

**Correction, 20 Oct.** Re-running `build_results.py` and `fold_stability.py` on the committed
dataset and code gives the figures in the tables here, under Python 3.14 and 3.15 alike, and at
both a9d54e4 and cee184e. The 0.7016 and 0.811 values, and the 20-seed means that went with them,
could not be reproduced from anything committed, so every model result was regenerated and the
report now quotes the reproducible values. New
templates changed which templates share a fold, and with three folds that alone moves both
models by several points.

## Fold stability

`scripts/fold_stability.py` repeats the grouped split under 20 seeds with the model seed held
fixed (`results/fold_stability.md`).

| Model | Mean macro F1 | SD | Min | Max |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.7423 | 0.0362 | 0.6796 | 0.7858 |
| Random Forest | 0.8449 | 0.038 | 0.7793 | 0.9234 |

Random Forest scored higher on all 20 seeds, so the ordering holds. The means are
also the stable figure: between the two regenerations on 16 Oct they moved by under 0.005
while the single-seed values moved by up to 0.08. The size of the gap does
not: a reader given one seed could be told anything from a near tie to a 0.15 lead. The
results chapter should report the mean and range, and treat the table above as one draw.

## The deterministic baseline is still not in that table

It scores 1.0 on every metric because the labels are its own output. That is arithmetic, not
evidence. While the labels come from one of the contestants the comparison cannot rank them,
and no rules versus models claim belongs in the results chapter. Breaking the circularity
needs the independent review of a sample (T112) and the disagreement log (T113).

## Against labels nobody on the project wrote (17 Oct)

AWS Security Hub and OpenSSF Scorecard publish a severity for some of the same
misconfigurations. `scripts/external_labels.py` matches each finding type to those controls,
with the documentation page for every match in `datasets/external_severity_map.csv`, and
scores the rules and the models against the published band.

| Predictor | Agreement with published band, 159 findings |
|---|---|
| Rules | 66.0% (Cohen's kappa 0.24) |
| Random Forest | 62.6% mean over 20 split seeds (47.2% to 75.5%) |
| Logistic Regression | 52.6% mean over 20 split seeds (43.4% to 75.5%) |

Seven of the eight referenced finding types agree with the rules exactly. The eighth carries
all the disagreement: a workflow token broader than read-only, which the rules place in medium
and OpenSSF Scorecard rates High, across 54 findings. The rule was not changed afterwards;
tuning it to the test would make the test meaningless.

So on the evidence an outside source can rate, Random Forest is level with the rules and
Logistic Regression is behind. That is a partial answer to RQ2, and the honest one: the models
do not beat the rules they learned from. It covers 159 of 711 findings. The other 552, mostly
committed state files and secrets, have no published severity at all, which is itself a gap in
the standards this project works against. A blind self-labelled sample (T112, part two) covers
those types, with the limitation that the labeller is the project's author.

## Blind labels (17 Oct)

Twenty findings, one per finding type, were labelled blind on a plain impact scale, without
the rule's band or the control id (`results/blind_label_check.md`). They agree with the rules on
15 of 20 (Cohen's kappa 0.49, moderate) and with the published severity on 7 of the 8 items
that have one.

The disagreements follow a pattern rather than scattering. In four of five, the rules say
high_or_critical and the blind label says medium, each time with the same reason: the finding
removes a protection, but an attacker still needs a further step before anything is exposed.
Bucket encryption removed, an unencrypted backend setting, a deleted or disabled public
access block. The rules treat a removed control as the exposure; the labeller treats it as the
precondition. The fifth runs the other way: a workflow token broader than read-only, medium
under the rules, high to the labeller and High under OpenSSF Scorecard. Two sources outside the
rules now place that finding higher, which makes it the clearest candidate for a rubric change
in future work. No rule was changed after the comparison.

## Leakage check

Logistic Regression, same data, four ways:

| Split | Rule inputs withheld | Rule inputs included |
|---|---:|---:|
| Grouped by template | 0.7685 | 0.8876 |
| Ungrouped (random) | 0.9166 | 1.0 |

On the small corpus the rule inputs made no difference under grouping, and the conclusion
recorded at the time was that grouping alone defeated the leak. **That conclusion was an
artefact of having too few templates.** With 57 templates, many of which share a
control id, the rule inputs lift the grouped score from 0.7685 to 0.8876, and an ungrouped
split with them reaches 1.0 - a perfect score that measures nothing except the model
rediscovering the lookup table.

Both defences are therefore doing work, and the earlier write-up understated the feature
exclusion. Grouping alone is worth 0.148 macro F1 of inflation avoided.

## Class support

| Band | Findings | Independent templates |
|---|---:|---:|
| high_or_critical | 507 | 39 |
| medium | 105 | 11 |
| non_security_or_low | 99 | 10 |

The high/critical class is much the largest, at 507
findings from 39 templates. That imbalance is a
property of the subject rather than of the sampling: most ways of mishandling Terraform state
expose it outright. Both models use balanced class weights, and macro F1 is reported precisely
because accuracy would flatter a model that simply guessed the majority class.

## What the model leans on

Top Random Forest importances:

- `detail_length` 0.1959
- `run_policy_status=compliant` 0.0985
- `run_policy_status=non_compliant` 0.09
- `persistence_across_runs` 0.0887
- `evidence_source=repository` 0.0665
- `assessment_coverage` 0.0593

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

The AWS drift runs are the part that is not synthetic. Nineteen ran on 16 Oct and are
recorded in D04b. They add 33 findings to 711, too few to change what the models learn, but
enough to move the single-seed scores, which is what the fold-stability section is about.

## Correction, 14 October 2026

An external review found that three of the sixteen features were constant across all 678
findings, so every number previously reported in this section was computed on thirteen
informative features rather than sixteen.

| Feature | Why it was dead |
|---|---|
| `is_remote_drift` | the column was never written to `findings.csv` by either writer |
| `run_policy_status` | the loader read `policy_status`; the column is `actual_policy_status` |
| `sensitive_data_involved` | looked for a `[REDACTED]` marker that never appears in a detail string |

With the joins fixed and the data regenerated, Logistic Regression moved from 0.6699 to
0.7789 and Random Forest from 0.5482 to 0.8198, which reverses the ordering
reported in the previous revision. The earlier claim that Logistic Regression led was an
artefact of a broken feature pipeline, not a finding about the models.

One feature remains constant: `in_history_only`. No generated scenario exercises a finding that
exists only in git history, so the feature has nothing to vary over. It is left in place and
reported here rather than dropped, because the capability it represents is implemented and
tested; the corpus simply does not cover it.

The lesson is methodological rather than technical. A feature that is silently constant does
not announce itself: the pipeline runs, the model trains, and the numbers look plausible. The
check that would have caught it is counting distinct values per feature before trusting any
model output, and it now runs as part of the results build.
