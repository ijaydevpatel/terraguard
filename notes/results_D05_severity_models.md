# D05 — Severity model comparison

Draft for the results chapter. 32 findings from 11 scenario templates, grouped
cross-validation with three splits, `random_state=20260916`.

## What the models are predicting

The label is the severity band that `severity_rules.py` assigns to a finding. The models see
context only — evidence source, resource type, attribute-path shape, whether the change was
remote, whether sensitive data was involved, run-level counts, assessment coverage. They
never see `control_id` or `normalised_event`, which are the two fields the rule ladder
switches on.

## Results

| Model | Macro F1 | Weighted F1 | Accuracy | Recall on high/critical |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.5687 | 0.5387 | 0.5625 | 0.2857 |
| Random Forest | 0.7714 | 0.7357 | 0.7500 | 0.4286 |

Random Forest is clearly ahead, which is the expected ordering. The rubric is a ladder of
conjunctions — *this control, unless another control still covers the same ground* — and a
tree splits on conjunctions natively while a linear boundary has to approximate them.

**Recall on the high/critical class is the number that matters operationally, and it is
poor.** Random Forest recovers 43% of severe findings from context; Logistic Regression 29%.
A prioritisation tool that misses more than half of the severe findings is worse than no
prioritisation, because it creates confidence that is not earned. That belongs in the
discussion as a limitation, not buried in a table.

## The deterministic baseline is not in that table

It scores 1.0 on every metric. That is arithmetic, not a result: the labels are the rules'
own output, so the rules reproduce them exactly by construction.

Listing that row next to the models would read as the baseline winning the comparison. It
did not win anything. While the labels come from one of the contestants, the comparison
cannot rank them at all.

This is the single most important qualification on this phase. Turning it into a real
comparison needs labels from outside the rules — the independent review of a sample (T112)
and the disagreement log (T113). Neither has been arranged. Until they are, no
rules-versus-models claim belongs in the chapter, and the RQ2 answer stays open.

## Leakage check

Logistic Regression, the same data, four ways:

| Split | Rule inputs withheld | Rule inputs included |
|---|---:|---:|
| Grouped by scenario template | 0.5687 | 0.5687 |
| Ungrouped (random) | 0.7186 | 0.9259 |

Two things fall out of this, and the first was a surprise.

**Grouping suppresses the rule-input leak entirely.** Handing the model `control_id` and
`normalised_event` changes the grouped score by nothing at all. The reason is that control
ids are almost perfectly confounded with scenario templates — BK-002 is the only template
that raises TG-P04 in that configuration — so when a template is held out, its control id
arrives as a category the model has never seen and carries no information. Under a random
split the same fields lift the score from 0.719 to 0.926, because then the model has seen
that exact control id in training.

**Grouping also matters without any rule inputs at all**: 0.7186 ungrouped against 0.5687
grouped. That gap is the cost of the honest split. A random split would have let variations
of the same template sit on both sides and inflated every figure in this chapter by roughly
fifteen points.

So the defence against leakage here is the grouping, not the feature exclusion. The
exclusion is still correct — it protects against a different failure, where a future
configuration has several templates sharing a control id — but the grouped numbers would
have been honest either way. That is worth stating plainly rather than claiming the feature
design did work the split was actually doing.

Separately verified: no scenario template appears on both sides of any fold
(`results/split_verification.json`). Asserted, not assumed.

## What the model is actually using

Random Forest importances, top five:

| Feature | Importance |
|---|---:|
| assessment_coverage | 0.2111 |
| detail_length | 0.1748 |
| resource_type=repository_file | 0.1206 |
| evidence_source=terraform_plan_json | 0.1185 |
| persistence_across_runs | 0.0716 |

This list is worth being suspicious of.

`assessment_coverage` is a property of the *run*, not of the finding. It is high when a
scenario supplies plenty of evidence and low when it supplies little, so it partly encodes
which scenario family a finding came from. `detail_length` is close to a fingerprint of the
message template a particular scanner emits. Neither is a security property, and a model
leaning on them is learning which scenario it is looking at rather than how dangerous the
finding is.

That is not leakage in the strict sense — both are legitimately available at prediction time
— but it does mean the model may generalise badly to findings from a scenario catalogue it
was not trained on. Dropping run-level features and re-running is the obvious next test, and
it is cheap.

## Weight these results can carry

Thirty-two findings across eleven templates, smallest class resting on three. Differences of
a few points between models are noise at this size, and no confidence interval computed from
three folds of this data would be meaningful.

The dataset also contains no infrastructure drift, so these numbers describe severity
prediction over repository, workflow and backend findings only.
