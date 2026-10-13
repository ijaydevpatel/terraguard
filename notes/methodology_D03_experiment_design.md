# D03 - Experiment design and dataset construction

Draft for the methodology chapter.

## What a record is

Two tables, two units.

`observations.csv` holds one row per **run**: a scenario replayed once, end to end. It
carries the run id, the scenario template, what the harness detected, whether that matched
the manifest, the assessment coverage and the processing time.

`findings.csv` holds one row per **finding**: a single control violation the pipeline
raised, joined back to its run by `run_id`. One run can produce several findings, or none.

The distinction is not bookkeeping. Severity is predicted per finding, and getting this
wrong cost a week. The first class audit read the scenario-level `expected_severity_band`
column and reported that no scenario produced a medium finding. That column is a summary of
the worst thing a scenario is expected to do. Measured properly, at finding level, the
pilot already contained medium findings - the token-scope violations in WF-001, which the
rubric places on rule 4 while the same scenario's artefact upload sits on rule 1. A
scenario is not one severity. It is a bag of findings with their own severities.

## The catalogue

Nineteen core templates, plus three marked optional and excluded unless asked for. Each has
a YAML manifest naming the injected change, the control it should trigger, the expected
normalised event and the expected severity band.

**Every manifest is written before the scenario is ever run.** A record with no prior
manifest is invalid and the harness refuses it. This is the ordinary defence against
deciding after the fact that whatever the tool found was what you meant to look for.

Thirteen templates are offline. They are committed fixtures - a `backend.tf` with local
state, a workflow YAML that uploads a plan, a plan JSON whose only drift is a tag value.
Nine require a deployed AWS baseline and have produced nothing so far, which is the largest
hole in the dataset and is discussed under threats to validity.

## The harness reads the answer, then looks away

`run_experiment.py` loads the manifest first, then sets it aside. Collection and assessment
run with no access to it. The comparison happens only when the row is written.

The alternative - passing the expected control into the scanners so the harness can
short-circuit - would make every detection figure in the results meaningless, because
detection would be able to see the answer while deciding.

A drift scenario invoked without a plan JSON exits non-zero rather than writing an empty
row. A short dataset is recoverable. A dataset that looks complete and is not is not.

## Variations and why the split groups them

Each template is replayed as five or six variations: a different port, an IPv4 or IPv6
address, the environment tag set to `test` or `production`. Ninety-seven core observations
are planned on that basis.

Those variations are near-duplicates of each other. An ordinary stratified split would put
some variations of a template in training and others in test, so the model would be scored
on near-copies of what it had already seen and the reported accuracy would be flattering
and wrong.

Evaluation therefore uses `StratifiedGroupKFold` grouped by scenario template. No template
appears on both sides of a split. The model is asked to generalise to scenario families it
has not seen, which is the claim the research needs to support. T114 asserts this rather
than assuming it.

The practical consequence is that **the number of independent groups, not the number of
rows, sets the ceiling on how the data can be split.** Adding more variations of the same
template adds rows and no information. This is why the W7 rebalance added seven new
templates rather than more replays.

## Class balance, measured at the right level

After the rebalance, running the frozen rules over the collected offline set gives:

| Band | Findings | Independent templates |
|---|---:|---:|
| high_or_critical | 14 | 4 |
| medium | 10 | 5 |
| non_security_or_low | 8 | 3 |

Minimum three templates in any class, so a three-split group-aware cross-validation is
feasible. A test now enforces that floor, because the audit was done by hand twice and
was wrong the first time.

One finding from the rebalance is worth keeping in the write-up. The first attempt added
four templates that produce medium findings and the non-security class still had a single
group. Clean negative controls produce **zero** findings by design - they measure the
false-alert rate and contribute nothing to training, because there is no row to label. The
non-security class needed scenarios that produce a finding which the rules then classify as
non-security: tag drift, a reworded description. A class is only populated by scenarios that
generate findings in it, which is obvious in hindsight and was not obvious at the time.

## Three classes, decided in advance

Five classes were dropped before any data was collected, not after the results came in.
Sixty to a hundred records cannot support five, so the class-count gate had only one
credible outcome and running it later would have been theatre. Recording the decision in
advance removes a contingency and makes the target explicit.

## Coverage travels with every compliance figure

The policy engine returns four outcomes, and `indeterminate` is the one doing the work. A
control that applies but could not be assessed is never reported as compliant.

Every run therefore also reports **assessment coverage**: the share of controls that reached
a definite answer. In the collected set it runs from 0.00 on a scenario whose only evidence
is a plan JSON to 0.88 on the clean controls. A compliance rate quoted without its coverage
cannot be interpreted - seven compliant controls means one thing when all eight were checked
and something quite different when four were never looked at. The results chapter reports
both together, always.

## Redaction happens before anything is written

The collector writes only the sanitised copy. The binary plan and the raw JSON live in a
temporary directory removed in a `finally` block, so there is no window in which an
unredacted artefact sits on disk.

Values are replaced shape-preservingly - `[REDACTED]:len=n:sha256:…` - rather than deleted,
so the feature builder can still tell that a secret was involved and the same secret can be
correlated across runs without the value being recoverable.

Fixtures carry synthetic markers only. Twelve pilot runs over fixtures seeded with
`TERRAGUARD_TEST_SECRET` markers produced zero markers in any output file.

## Where the labels come from, and the problem with that

This is the part that most needs stating plainly, because it decides what the model
comparison is allowed to claim.

`severity_rules.py` is a transcription of the rubric in `docs/SEVERITY_RUBRIC.md`: a
five-rule ladder with overrides for direction, out-of-band deletion and detection controls
that another control still covers. It was frozen before any model was trained. Every label
it returns carries the number of the rule that produced it, so a reviewer can disagree with
a rule rather than with an impression.

It is also the **comparator**. If Logistic Regression and Random Forest cannot beat a lookup
table, that is a result worth reporting - and it is only reportable if the table was fixed
first.

The difficulty: those same rules currently supply the labels. The rules are a deterministic
function of the control id and the normalised event. If those two fields are also given to
the model as features, the model is being handed the answer key and will score close to
perfect while learning nothing. That is not a model result. It is a restatement of the
lookup table.

Two consequences for the design:

1. **The rule inputs are withheld from the feature set.** The models predict severity from
   the surrounding evidence - resource type, evidence source, attribute path, whether the
   change was remote, whether sensitive data was involved, how many findings the run
   produced, coverage - not from the fields the ladder switches on. T076 checks this
   explicitly rather than trusting it. Both configurations will be reported: with the rule
   inputs included, as a demonstration of what leakage looks like, and without them, as the
   actual experiment.

2. **Rule-derived labels are not ground truth.** They are one analyst's rubric applied
   consistently. The independent review of a sample (T112) and the disagreement log (T113)
   are what would turn them into something defensible, and neither has happened. Until they
   do, the honest framing is that the models are being tested on whether the severity a
   rubric assigns can be recovered from context - not on whether they predict severity
   correctly in any absolute sense.

## Threats to validity

**The drift half of the dataset is empty.** Nine templates covering security-group exposure,
encryption, public access, IAM privilege, logging and out-of-band deletion need a deployed
baseline. None has run. Infrastructure drift is the project's headline claim and it is
currently supported by fixtures alone. Nothing in the results chapter may imply otherwise.

**The study is small.** Twenty-six observations and thirty-two findings collected so far,
against ninety-seven planned. Three independent groups in the smallest class is the minimum
that permits a split, not a comfortable margin. Confidence intervals will be wide and should
be reported as such rather than quoted as point estimates.

**Labels are single-analyst.** Addressed above; the mitigation is not yet in place.

**Scenarios are synthetic and author-designed.** The same person wrote the detection rules
and the scenarios that exercise them. The clean negative controls are a partial defence -
they show the scanner is not simply flagging everything - but a scenario catalogue written
by the tool's author will favour the tool. An external corpus such as TerraGoat would test
this, and is currently optional scope.

**No second implementation checks the control decisions.** The Checkov comparison was cut to
optional. Controls are traced to HashiCorp, AWS Config and GitHub Actions documentation, so
they are not invented, but a systematic misreading of a rule would currently go unnoticed.
