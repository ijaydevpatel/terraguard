# D04 - Detection and policy assessment results

Draft for the results chapter. Figures come from the generated corpus plus the original
hand-built fixtures: 684 observations and 678 findings across 56 scenario templates. Every
configuration was written to disk and scanned by the real pipeline. None of it came from a
live AWS account. The 19 live AWS observations from 16 Oct are reported separately in D04b
and are not pooled into these figures.

## Detection against ground truth

| Measure | Result |
|---|---|
| Runs where the manifest's control was raised | 684 / 684 |
| Runs where policy status matched the manifest | 684 / 684 |
| Negative control runs | 120 |
| Security findings on negative controls (false alerts) | 0 |
| Non-security findings on negative controls | 72 |

The last two rows need separating, and conflating them is a mistake I made the first time.
The tag and description drift families are expected to stay policy compliant and still raise a
finding, because a tag did change and the tool noticed. Counting those as false alerts
reported 72 of them while nothing was wrong. A false alert is a security band finding on a
scenario that should raise none, and there are none across 120 negative controls.

Detection at 684 of 684 is not evidence of a hard problem solved. Each scenario was generated
with a known violation and the scanner looks for exactly that class of violation, so the
figure measures internal consistency rather than difficulty. What it does establish is that
every control fires when it should and no control fires when it should not, across a corpus
wide enough that a silent gap would show up. Four of them did, and are listed below.

## Assessment coverage

Coverage ranges from 0.00 to 0.875.

Both extremes are informative. A scenario whose only evidence is a plan JSON leaves every
repository and workflow control indeterminate and reads 0.00: the tool knows it cannot answer.
The richest scenarios reach 0.875, with the remaining control needing live AWS evidence.

This is why compliance is never reported on its own. Seven compliant controls out of eight
means one thing when all eight were assessed and something quite different when four were
never looked at. The policy engine returns indeterminate rather than compliant whenever
evidence is missing or unreadable, and a named test asserts it.

## Processing time

| | ms |
|---|---:|
| Minimum | 22.3 |
| Median | 96.5 |
| Maximum | 393.0 |

Measured per run with no network calls. The spread tracks how much evidence a scenario
carries rather than anything about the analysis: plan JSON scenarios sit at the bottom,
repository scans with a history walk at the top. These are not comparable to a live run, which
would be dominated by `terraform plan -refresh-only` round-tripping to AWS.

## Data quality

No orphan runs, no blank required fields, and zero duplicate identifiers across 678 findings.

The duplicate `(run_id, finding_id)` pairs reported earlier are fixed. The cause was that
`finding_id` was built from the file path and control id alone, so a workflow violating TG-P07
twice, once by uploading a plan artefact and once by writing state paths to the Actions cache,
produced two genuinely different findings sharing one identifier. That inflated the
`persistence_across_runs` feature, which the models use. Workflow finding ids now carry a short
discriminator taken from the detail.

## Detection gaps this corpus exposed

Building the corpus found four defects the small fixture set had never exercised. Each was a
silent failure rather than a visible one, which is the kind that survives to submission.

**Drift findings carried no control id.** The policy engine matches findings to controls by id
and nothing else, so TG-P10, TG-P11 and TG-P12 could never be marked non-compliant from drift.
Detection worked and assessment quietly did not, so a run with a security group open to the
world reported as compliant. Fixed with an explicit event to control table.

**Out-of-band deletion had no control at all.** A resource deleted outside Terraform was
detected and then assessed as compliant, because nothing covered it. TG-P13 was added.

**Encryption removal read as an ordinary value change.** An algorithm name emptied out
categorises as value to absent, while the normaliser required enabled to disabled. Turning
encryption off produced no finding.

**A public access block switched off was classified as housekeeping.** It reads as enabled to
disabled rather than restricted to public, so it fell through to non-security operational
drift.

There was also one false positive, surfaced by the tool's own secure fixture: `id-token: write`
in a workflow permissions block was reported as a leaked secret because the key contains the
word token. It is a permission scope, not a credential.

All five are fixed and covered by tests. They are reported here rather than quietly patched,
because a detection tool that has never been shown to fail has usually not been tested hard
enough.

## A detection gap that is not fixable in this tool

The first live dry run surfaced something the synthetic corpus could not. The pre-flight
reported the baseline clean while the security group was already open to the world, and both
reports were correct.

The baseline manages ingress as individual `aws_vpc_security_group_ingress_rule` resources, one
Terraform resource per rule. A rule added out of band has no corresponding state entry, so
`terraform plan -refresh-only` has nothing to compare it against and emits an empty
`resource_drift`. Terraform is behaving as documented: it reconciles the resources it manages,
and an unmanaged rule is not one of them.

This bounds the whole approach rather than this implementation. Every control in this project
that depends on refresh output - TG-P10 through TG-P13 - can only see drift in resources
Terraform already tracks. Modified attributes are visible. Added resources are not. A tool built
on `terraform plan` cannot close that gap; closing it needs a second evidence source that
enumerates actual cloud state, such as AWS Config or a direct API sweep, which is named as
further work rather than claimed here.

Two consequences were acted on. SG-001 was rewritten to modify the managed rule's CIDR rather
than add a new rule, so the scenario produces detectable drift of the same severity. And the
orchestrator now treats an injected change that yields empty `resource_drift` as a failed
scenario rather than a passing one, because a scenario that detects nothing and reports success
is the worst possible outcome.

The original injection is retained behind a flag so the negative result can be reported from
evidence rather than from argument.

## What these results do not support

The corpus is synthetic. Every configuration was written by a generator I designed, so the
findings are genuine detections of real misconfigurations drawn from a population of my own
choosing. It is not a sample of what engineers actually commit.

Infrastructure drift is the project's headline claim, and the drift evidence here comes from
plan JSON documents built to specification rather than captured from a live refresh. The AWS
runs recorded in the runbook are the part that is not synthetic, and they are reported
separately rather than pooled with these figures.
