# D06 - Discussion, limitations and threats to validity

## What the project establishes

Terraform state exposure is detectable from evidence a repository already carries. Across
684 synthetic runs over 56 scenario families the pipeline raised the expected control every
time and raised no security finding on 120 negative controls. Planting a real-format AWS key
and a state file in a repository shows the tool finds both, never reprints either value, and
stops the commit landing. Detection without prevention is a report nobody acts on, so that
last part is the claim worth making.

Drift detection also works against real infrastructure. On 16 Oct, seven kinds of change were
made to a deployed AWS baseline through the API, six of them three times each. All 18 of
those runs were detected and matched their ground truth, the security changes failed the gate
and the tag change passed it, and every restore came back clean (D04b). The seventh kind,
removing S3 default encryption, produced no drift at all, for a reason covered below.

The second contribution is less comfortable. Building a corpus wide enough to train on exposed
five defects that a small fixture set had hidden, four of them silent: detection worked and
assessment quietly did not. A security group opened to the world was reported as compliant.
The live run found three more problems of the same kind, none of which any offline test could
reach: two ground-truth manifests that named the wrong control, a restore that reported drift
which was not there, and a Terraform exit code that contradicted its own output.

## What it does not establish

**The severity question is unanswered.** The labels come from the same rubric the deterministic
baseline implements, so the baseline scores 1.0 by construction and cannot be ranked against the
models. Across 20 grouped split seeds, Logistic Regression averages 0.73 macro F1 (0.60 to 0.80)
and Random Forest 0.80 (0.66 to 0.86), with the forest ahead on 17 of 20. Both are predicting
one analyst's rubric from context, not predicting severity. Closing this needs labels from
outside the rules (T112), which takes a person rather than more code.

**The corpus is mostly synthetic.** Every configuration in the 684 synthetic runs was written by
a generator I designed. The findings are genuine detections of real misconfigurations, but the
population is mine and not a sample of what engineers commit. Nineteen live rows do not change
that balance. An external corpus such as TerraGoat would test the parser against configurations
nobody here wrote.

**Three live runs per scenario is not a detection rate.** D04b shows the chain working on every
attempt, but 18 runs over six scenarios cannot bound how often it fails. The live
signal-to-noise ratio (four findings for one SG change, against one on the fixture) was
measured on a single scenario.

## Threats to validity

**Circular labelling.** Covered above, and the single largest threat. Risk R20.

**Single-seed model figures.** Adding the live findings moved Logistic Regression from 0.7789 to
0.7016 and Random Forest from 0.8198 to 0.811 at a fixed seed, by way of 0.8874 in between,
with the old data still reproducing the old numbers exactly. The 20-seed means moved by under
0.005 over the same changes. With three grouped folds, which templates share a fold matters about as much
as the model. Any single macro F1 in this project should be read with the fold-stability range
beside it (`results/fold_stability.md`).

**Ground truth written by the tool's author.** S3-002 and DEL-001 named a control that their own
expected event does not map to. The tool was right both times and the manifests were wrong, and
nothing caught it until a live run. The corrections are dated and keep the original value, and a
test now enforces the event-to-control mapping, but it shows the manifests were not an
independent check. The same person wrote the detection rules and the scenarios that exercise
them, so the catalogue will favour the tool. The negative controls are only a partial defence.

**Scenarios that cloud behaviour can invalidate.** S3-001 removes a bucket's default encryption.
Since January 2023 S3 encrypts every bucket with SSE-S3 regardless, so the injection left the
bucket matching its baseline and there was no drift to detect. A scenario designed against
documentation can stop meaning anything when the platform changes, and only a live run shows it
(R28).

**A detection gap shared by every plan-based tool.** A resource added out of band, such as a new
security group rule with no state entry, is invisible to `terraform plan -refresh-only` (R25).
The live SG scenario widens a managed rule instead, so the gap is documented rather than measured.

**Features that encode scenario identity.** `detail_length` is the strongest Random Forest
feature at 0.20, and it is closer to a fingerprint of which scanner wrote the message than to
anything about danger. A model leaning on it will generalise badly to a catalogue it was not
trained on.

**Class imbalance.** 507 of 711 findings are high or critical, because most ways of mishandling
state expose it outright. Both models use balanced weights and macro F1 is reported for that
reason, but the smallest class rests on 10 independent families.

**An API limit the scenario design missed.** IAM-001's third run failed with LimitExceeded: a
managed policy keeps at most five versions and every injection adds one. Nothing was changed
before the failure, and the script now prunes old non-default versions first. Repeated live
runs find limits that one run never reaches.

**Few independent checks on control decisions.** Controls are traced to HashiCorp, AWS Config and
GitHub Actions documentation. The Checkov comparison (`results/checkov_comparison.md`) gives a
second implementation for the static controls, and it found a false positive in this project's
own bootstrap. It does not cover drift.

**Single environment.** One AWS account, one region, Terraform 1.16.5, AWS provider 5.100.0.
Terraform's refresh-only exit code already behaved differently from its documentation in this
version, which is a reason to pin what was tested rather than claim generality.

## What I would do next

Get twenty findings labelled by someone else, which turns RQ2 from unanswerable into answered
either way. Replace S3-001 with an SSE-KMS to SSE-S3 downgrade and add a second evidence source,
such as AWS Config, for resources added out of band. Re-run the models without run-level and message-shape features and report the range
across seeds, not one split.
