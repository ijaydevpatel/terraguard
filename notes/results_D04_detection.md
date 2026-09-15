# D04 — Detection and policy-assessment results

Draft for the results chapter. All figures are from the offline half of the dataset:
26 observations and 32 findings across 13 scenario templates, each template replayed twice.
The nine AWS drift templates have never run, so nothing here covers infrastructure drift.

## Detection against ground truth

| Measure | Result |
|---|---|
| Runs where the manifest's control was raised | 26 / 26 |
| Runs where policy status matched the manifest | 26 / 26 |
| Clean negative-control runs | 4 |
| Findings raised on clean runs (false alerts) | 0 |

Every scenario raised the control its manifest named, and no other control was raised in
error. The clean controls produced nothing at all.

The false-alert figure matters more than the detection count, and it should be read that
way in the chapter. A scanner that flags a clean repository gets switched off within a week,
so zero findings on four clean runs is the more useful result — even though four runs is a
thin basis for it, and the write-up should say so rather than quoting 0% as if it were
established.

Detection at 26/26 is not evidence of a hard problem being solved. These are repository and
workflow scenarios where the signal is a committed file or a YAML key, and the scanner looks
for exactly that. The number would be worth much more if it came from injected drift in a
live account, which is the half that has not run.

## Assessment coverage

Coverage ranges from 0.00 to 0.88 across the collected runs.

The extremes are both informative. A scenario whose only evidence is a plan JSON leaves
every control indeterminate and reads 0.00: the tool knows it cannot answer. The clean
controls reach 0.88, with the remaining control needing live AWS evidence that does not
exist.

This is the reason compliance is never reported alone. Seven compliant controls out of eight
means one thing when all eight were assessed and something quite different when four were
never looked at. The policy engine returns `indeterminate` rather than `compliant` whenever
evidence is missing or unreadable, and a named test asserts that it does.

## Processing time

| | ms |
|---|---:|
| Minimum | 148 |
| Median | 391 |
| Maximum | 569 |

Measured per run on the offline path with no network calls. The spread tracks how much
evidence a scenario carries rather than anything about the analysis: the plan-JSON scenarios
sit at the bottom, the workflow scenarios with a git-history walk at the top.

These are not comparable to a figure from a live run, which would be dominated by
`terraform plan -refresh-only` round-tripping to AWS. The local-versus-CI comparison in
T102 is where a meaningful timing claim would come from.

## Data quality

The pass over the collected dataset found no orphan runs and no blank required fields.

It did find two duplicate `(run_id, finding_id)` pairs, both in WF-001. The cause is that
`finding_id` is built from the file path and the control id, so a workflow that violates
TG-P07 twice — once by uploading a plan artefact, once by writing state paths to the Actions
cache — produces two genuinely different findings that collide on one identifier.

This is a real defect rather than a cosmetic one. The `persistence_across_runs` feature
counts how often a finding id recurs, so a collision inflates that count for the affected
rows. It is recorded as a defect to fix rather than quietly deduplicated, because dropping
one of the two would discard a real finding.

## What these results do not support

The headline claim of the project is drift detection, and none of the above tests it. The
detection figures come from scanners reading committed files and workflow YAML. Every drift
capability — security-group exposure, encryption, public access, IAM privilege, logging,
out-of-band deletion — has been exercised against fixtures only, because the AWS account
does not exist.

Any sentence in the chapter that says the tool detects infrastructure drift must be
qualified with "against synthetic plan JSON", until T021 changes that.
