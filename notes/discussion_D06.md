# D06 - Discussion, limitations and threats to validity

## What the project establishes

Terraform state exposure is detectable from evidence a repository already carries. Across
684 runs over 56 scenario families the pipeline raised the expected control every time
and raised nothing on 120 negative controls. More usefully, planting a real AWS key and a state
file in a repository shows the tool finds both, never reprints either value, and stops the
commit landing. That last part is the claim worth making: detection without prevention is a
report nobody acts on.

The second contribution is less comfortable and more interesting. Building a corpus wide enough
to train on exposed five defects that a small fixture set had hidden, four of them silent
failures where detection worked and assessment quietly did not. A security group opened to the
world was being reported as compliant. That is the failure mode this kind of tool is most
likely to ship with, because nothing goes red when it happens.

## What it does not establish

**The severity question is unanswered.** The labels come from the same rubric the deterministic
baseline implements, so the baseline scores 1.0 by construction and cannot be ranked against the
models. Logistic Regression reaches 0.6699 macro F1 and Random
Forest 0.5482, but both are predicting one analyst's rubric from
context rather than predicting severity. Closing this needs labels from outside the rules, which
is a person rather than more code.

**The corpus is synthetic.** Every configuration was written by a generator I designed. The
findings are genuine detections of real misconfigurations, but the population they are drawn
from is mine, and it is not a sample of what engineers actually commit. An external corpus such
as TerraGoat would test the parser against configurations nobody here wrote.

**The drift evidence is not from a live account.** Plan JSON documents were built to
specification rather than captured from `terraform plan -refresh-only` against deployed
infrastructure. The runbook records how to collect the real thing, and those runs are reported
separately rather than pooled with these figures.

## Threats to validity

**Circular labelling.** Covered above, and the single largest threat. Risk R20.

**Author bias in scenario design.** The same person wrote the detection rules and the scenarios
that exercise them, so the catalogue will favour the tool. The negative controls are a partial
defence - they show the scanner is not simply flagging everything - but only a partial one.

**Features that encode scenario identity.** `detail_length` is the strongest Random Forest
feature at 0.2945, and it is closer to a fingerprint of which
scanner wrote the message than to anything about danger. A model leaning on it will generalise
badly to a catalogue it was not trained on. This is stated rather than fixed, and dropping
message-shape features is the obvious next experiment.

**Class imbalance.** 486 of 678
findings are high or critical, because most ways of mishandling state expose it outright. Both
models use balanced weights and macro F1 is reported for exactly this reason, but the smallest
class still rests on 8 independent families.

**No second implementation checks the control decisions.** Controls are traced to HashiCorp,
AWS Config and GitHub Actions documentation, so they are not invented, but a systematic
misreading would go unnoticed. The Checkov cross-check was cut to optional scope.

**Single environment.** One AWS account, one region, one Terraform version. Provider behaviour
differs across versions and the reproducibility record pins what was tested rather than claiming
generality.

## What I would do next

Get twenty findings labelled by someone else, which turns RQ2 from unanswerable into answered
either way. Run the drift scenarios against the deployed baseline, which moves the headline
claim off synthetic evidence. Then re-run the models without run-level and message-shape
features and report whichever result is honest.
