# Design decisions log

Append-only. Every entry here becomes a paragraph in the methodology or discussion chapter.
Record the decision, the alternatives considered, and why the alternative lost.

---

## 2026-07-28 - P0/P1 foundations

**Redaction runs on write, not on read.**
Alternative: sanitise at report time. Rejected because the raw plan JSON would then exist on
disk for the lifetime of a run, and every intermediate artefact becomes a leak surface. The
collector now writes only the sanitised copy; the binary plan and raw JSON live in a
`tempfile.mkdtemp` directory removed in a `finally` block.

**Redaction preserves shape rather than deleting values.**
Values become `[REDACTED]:len=n:sha256:xxxxxxxxxxxx`. Rejected alternative: a bare
placeholder. Shape preservation lets the feature builder still compute
`sensitive_data_involved` and lets the same secret be correlated across runs, which the
`persistence_across_runs` feature needs, without the value being recoverable.

**Provider sensitivity flags are not trusted alone.**
The plan JSON `before_sensitive` / `after_sensitive` trees are honoured, but a key-name regex
and a value-shape regex run as well. Provider coverage of the sensitive flag is inconsistent,
and a missed secret is unrecoverable once published.

**An offline path is mandatory for every module.**
`collect_from_plan_json` builds an evidence bundle from an existing plan JSON with no
Terraform binary and no credentials. This keeps the test suite runnable in CI, keeps the tool
demonstrable if AWS access lapses, and is the mitigation for risk R1.

**Dataclasses rejected in favour of pydantic for the record types.**
Validation at the boundary matters more than import speed here: the observation CSV must not
be polluted by a malformed finding, and enum coercion catches typos in scenario manifests.

**Terraform baseline uses `aws_vpc_security_group_ingress_rule`, not inline `ingress` blocks.**
Inline blocks produce a single diff on the whole security group, which makes the changed
attribute path ambiguous. Discrete rule resources give one drift record per rule, which is
what the parser and the `expected_attribute` ground-truth field need.

**`prevent_destroy` is off on the state bucket.**
Deliberate, for a research environment that must be torn down cleanly. Noted as a deviation
from what production guidance would require, and flagged in the limitations section.

**environment is a Terraform variable with validation, not a hardcoded tag.**
Scenario variations need to relabel the same infrastructure as `test` or `production` to test
whether the severity ranking shifts with environment. Only `test` is ever deployed.

---

## 2026-07-28 - CI, first run

**Checkov is installed in its own virtual environment, not in `requirements-dev.txt`.**
Alternative: keep it in the dev requirements and loosen the project's `boto3` pin to
accommodate it. Rejected because checkov 3.2.200 pins `boto3==1.34.25` exactly, so pip's
resolver fails outright (`ResolutionImpossible`) - which is how the first CI run failed after
11 seconds. Letting a comparison benchmark dictate the project's own dependency versions is
the wrong trade: `boto3` is used by the scenario injection scripts and the backend checks,
where the version matters, whereas checkov is only invoked as an external command in Phase 4
and is never imported by the package. `requirements-checkov.txt` plus a `.venv-checkov`
environment keeps the benchmark available without coupling.
Evidence: `requirements-dev.txt`, `requirements-checkov.txt`, CI run #1.

**The CI job runs the security guard and the tests before the linters.**
Alternative: lint first, as most templates do. Rejected because a formatting nit would then
fail the job before the state-file guard or the test suite had reported anything, which
obscures the failure that actually matters. Substance first, style second.
Evidence: `.github/workflows/ci.yml`.

---

## 2026-07-28 - supervisor review response

**State locking moved from DynamoDB to S3-native `use_lockfile`.**
Alternative: keep the DynamoDB lock table. Rejected because Terraform 1.10 introduced
S3-native locking through a conditional write, and 1.11 deprecated the `dynamodb_table`
backend argument, which HashiCorp will remove in a future minor version. Building a
research prototype on a deprecated path would age badly across the life of the project.
The native lock also removes a resource, its IAM surface and its cost from the environment.
Terraform floor raised from 1.7 to **1.11**.
Evidence: `terraform/bootstrap/state_backend.tf`, `outputs.tf`, `terraform/baseline/backend.tf`.

**`ap-southeast-2` (Sydney) retained even though a New Zealand region now exists.** *Superseded on 14 October 2026, see below.*
AWS opened `ap-southeast-6` (Auckland) on 2 September 2025, so the earlier justification -
"nearest mainstream region" - was wrong. Sydney is kept on different grounds: broader service
catalogue and substantially more documentation, which outweighs the latency saving for a
prototype. The point is that the region is now a recorded decision with a stated reason,
not an unexamined default.
Evidence: `terraform/bootstrap/variables.tf`, `docs/AWS_SETUP.md`.

**Scope reduced from a 424 h plan to a 101 h plan.**
The original estimate was roughly four times the scale agreed for a STEM research project.
Re-baselining exposed an inconsistency worth recording: P0 and P1 had been estimated at 70 h,
which would have consumed 70% of a 100 h budget on scaffolding. Every estimate was rescaled,
including retrospectively - P0/P1 is now 18 h, which reflects what was actually built.
Scope cuts: 12 controls to 8, 20-30 scenario templates to 10-12, 200-300 observations to
60-100, five severity classes to three, four report formats to two (terminal and JSON), and
the Checkov comparison and TerraDS robustness pass dropped unless the freeze is met early.
Consequence: 83 h remain across ~11.5 weeks, about 7 h/week. Time is no longer the binding
constraint - AWS availability and the wall-clock duration of the experiment runs are.

**Three severity classes chosen up front rather than decided after data collection.**
Alternative: keep five classes and run the W7 class-count gate. Rejected because 60-100
records cannot support five classes, so the gate had only one credible outcome. Deciding now
removes a contingency from the plan and makes the target explicit before any data is gathered.

**Model evaluation will use `StratifiedGroupKFold`, grouped by scenario template.**
Alternative: an ordinary stratified split. Rejected because each scenario template is replayed
as 8-12 variations (port, IP family, environment label). A random stratified split would place
variations of the same template on both sides of the split, so the model would be tested on
near-duplicates of what it trained on and the reported accuracy would be optimistic. Grouping
by template forces generalisation to unseen scenario families, which is the claim the research
actually needs to support.
Evidence: to be implemented in `model_trainer.py` (Phase 7).

---

## Template for new entries

```
## YYYY-MM-DD - <phase / task id>

**<Decision in one sentence.>**
Alternative: <what else was considered>. Rejected because <reason>.
Evidence: <file, test, or report artefact that shows it>.
```

---

## 2026-08-11 - Phase 5 pilot

**The harness reads the manifest, then sets it aside until the row is written.**
Alternative: pass the expected control into the scanners so the harness can short-circuit.
Rejected because detection would then be able to see the answer while deciding, and every
detection figure in the results would be worthless. `run_experiment.py` loads the manifest
first, runs collection and assessment blind, and compares only at the end.
Evidence: `scenarios/run_experiment.py`, `tests/test_experiment_harness.py`.

**A drift scenario with no plan JSON fails loudly rather than writing an empty row.**
Alternative: skip silently and carry on. Rejected because a partial dataset that looks
complete is worse than one that is visibly short. Running SG-001 without a deployed baseline
exits non-zero and says why.
Evidence: `test_drift_scenario_without_a_plan_is_refused_not_guessed`.

**Assessment coverage is reported with every run.**
The pilot made the reason concrete. ST-001 supplies repository evidence only, so seven of
eight controls return indeterminate and coverage reads 0.12; the clean controls reach 0.88.
A compliance rate quoted without its coverage cannot be interpreted, so the results chapter
reports both together.

**Severity is recorded as a band from the manifest, not as a label.**
The `deterministic_severity` column exists but is empty until Phase 6 fills it. Adding the
column now means populating it later is not a schema change. Final labels need the rubric in
`docs/SEVERITY_RUBRIC.md` and a review sample from someone other than the author (T112);
until then the column carries no weight.

---

## 2026-08-22 - deterministic baseline, and a correction to the class audit

**The deterministic severity table is frozen before any model is trained.**
Alternative: tune the rules after seeing model results. Rejected because the table is the
comparator: if Logistic Regression and Random Forest cannot beat a lookup table, that is
only reportable if the table was fixed first. Every label carries the rule number that
produced it, so a reviewer can disagree with a rule rather than with an impression.
Evidence: `terraguard/severity_rules.py`, `tests/test_severity_rules.py`.

**Correction: the medium class is not empty. The class audit measured the wrong unit.**
The audit on 21 Aug read `expected_severity_band` from the scenario catalogue and concluded
that no scenario produces a medium finding. That column is a scenario-level summary, but the
models predict severity **per finding**, and one scenario can produce findings in different
bands. Running the frozen rules over the pilot's 16 findings gives 14 high-or-critical and
2 medium - the medium pair being the TG-P08 token-scope findings from WF-001, which fall on
rule 4.

The conclusion changes but the problem does not. At finding level the independent groups are
still four templates for high-or-critical and one for medium, which is not enough to split.
The rebalance in W7 is still needed; what changed is that it must be specified in terms of
findings per template, not scenarios per band.
Evidence: `datasets/findings.csv`, run of `severity_rules.classify` over the pilot.

**`deterministic_severity` in observations.csv is the worst band any finding in that run
earned.** A run-level summary is not the training label - the training label is per finding.
The column is kept because it makes a run scannable by eye, and the per-finding labels are
derived from `findings.csv` at training time.

---

## 2026-08-22 - W7 catalogue rebalance

**Clean controls measure false alerts but contribute nothing to training.**
This is what the first rebalance attempt missed. CLEAN-001 and CLEAN-002 produce zero
findings by design, so they generate no rows to label. The non-security class needs
scenarios that produce a finding which the rules then classify as non-security - tag and
description drift - not scenarios that produce nothing.
Evidence: after adding four medium templates the non-security class still had one group;
adding TAG-002/003/004 took it to three.

**The 10-12 template ceiling was raised to 19.**
Alternative: keep the ceiling and accept an untrainable dataset. Rejected. The ceiling came
from an hours argument during the 100-hour rescope, and the seven templates added are all
offline fixtures - a committed backend.tf, workflow YAML or plan JSON - costing no AWS time
and no experiment wall-clock. The hours argument does not apply to them. Core observations
are 97, still inside the 60-100 band.
Evidence: `datasets/scenario_catalogue.csv`, `test_catalogue_has_enough_core_templates_to_train_on`.

**Group counts are now asserted by a test rather than audited by hand.**
`test_every_severity_class_has_at_least_three_independent_templates` fails the build if any
class drops below three templates. The class audit found this problem twice by hand, on two
different units of analysis, and got the unit wrong the first time.
Evidence: `tests/test_scenario_catalogue.py`.

---

## 2026-09-16 - W8/W9 models, and what the comparison can claim

**The deterministic baseline was removed from the comparison table.**
Alternative: report it at 1.0 alongside the models. Rejected because the labels are the
baseline's own output, so 1.0 is arithmetic rather than evidence, and a reader scanning the
table would take it as the baseline beating the models. While the labels come from one of the
contestants the comparison cannot rank them at all. The row is described in prose with its
reason instead. A rules-versus-models claim needs labels from outside the rules, which is
T112 and T113, and neither is arranged - so the RQ2 answer stays open.
Evidence: `results/model_comparison.md`, `notes/results_D05_severity_models.md`.

**Grouping, not feature exclusion, is what defeats the control-id leak.**
The leakage check was run four ways. Under grouped folds, adding `control_id` and
`normalised_event` changes macro F1 by nothing (0.5687 either way). Under a random split the
same fields lift it from 0.7186 to 0.9259. Control ids are almost perfectly confounded with
scenario templates, so a held-out template contributes a category the model has never seen.
The feature exclusion is kept because it protects against a future catalogue where several
templates share a control id, but the write-up must not claim the exclusion did work the
split was actually doing.
Evidence: `results/leakage_matrix.json`.

**The same check also priced the honest split.** Without any rule inputs, ungrouped scoring
reaches 0.7186 against 0.5687 grouped. A random split would have inflated every figure in the
results chapter by roughly fifteen points.

**Run-level features are being treated as suspect.**
`assessment_coverage` (0.21) and `detail_length` (0.17) are the two strongest Random Forest
importances, and neither is a security property. Coverage is a property of the run and partly
encodes which scenario family produced the finding; detail length is close to a fingerprint of
a scanner's message template. Not leakage - both are available at prediction time - but a
model leaning on them may generalise badly to a catalogue it was not trained on. Re-running
without run-level features is the next test.

**`finding_id` is not unique, and the duplicates are not being deduplicated.**
The id is built from file path plus control id, so a workflow violating TG-P07 twice - once by
uploading a plan artefact, once by writing state paths to the Actions cache - produces two
genuinely different findings on one id. This inflates `persistence_across_runs` for the
affected rows. Recorded as a defect (T124) rather than dropped, because discarding either row
would discard a real finding.
Evidence: `results/duplicate_audit.json`.

---

## 2026-10-14 - region changed to us-east-1

**The deployment region moved from `ap-southeast-2` to `us-east-1`.**
Alternative: keep Sydney, which the earlier entry argued for on service catalogue breadth and
documentation volume. Rejected because the account owner works in us-east-1, and the earlier
reasoning never weighed who would actually operate the environment. A region chosen for a
marginal service-maturity argument is worse than one the operator is set up for, particularly
in a project where every AWS step is run by hand.

The change touches the live stacks, the bootstrap variables, the injection helpers and the
pipeline. The synthetic fixtures still carry the old region string, deliberately: they are test
data whose region is arbitrary, and rewriting them would churn the dataset and the committed
results for no gain.

Consequence for the write-up: latency is no longer a stated consideration, and the limitations
section should say the experiment ran in a single region without claiming that region was
selected on technical grounds.
Evidence: `terraform/bootstrap/variables.tf`, `terraform/baseline/variables.tf`, `docs/RUNBOOK.md`.
