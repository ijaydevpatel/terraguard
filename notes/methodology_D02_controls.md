# D02 - The control catalogue and where it comes from

Draft for the methodology chapter.

## Why eight

The first catalogue had twelve controls. After the supervisor review cut the project back to
roughly 100 hours, twelve stopped being defensible: each control needs a decision rule, a
citation, a scenario that triggers it and a test, and twelve of those was more work than the
detection pipeline itself.

Eight are core. Four remain in the repository marked `tier: optional` and are loaded only
when `load_controls(include_optional=True)` is called. They were not deleted, because the
reasoning behind them is written down and a later project could pick them up.

## The eight

| ID | Control | Evidence | Severity if violated |
|---|---|---|---|
| TG-P01 | State and plan files are not committed to Git | repository | high |
| TG-P02 | State uses a secure remote backend | backend_config | high |
| TG-P03 | State bucket encryption is enabled | backend_config | high |
| TG-P04 | State locking is configured and not deprecated | backend_config | medium |
| TG-P05 | State bucket versioning is enabled | aws_api | medium |
| TG-P06 | Sensitive output is not exposed in logs or tracked files | workflow | critical |
| TG-P07 | Saved plans are not uploaded as artefacts or cached | workflow | high |
| TG-P08 | GitHub Actions uses least-privilege token permissions | workflow | medium |

Optional: TG-P09 short-lived credentials, TG-P10 public network access, TG-P11 wildcard IAM
privilege, TG-P12 encryption and logging remain enabled.

## Where each one comes from

Nothing here was invented. A control with no source is an opinion, and an opinion cannot be
defended in a viva.

**HashiCorp documentation** gives TG-P01, TG-P02, TG-P04 and TG-P07. The state
sensitive-data page is explicit that state can contain secrets in cleartext; the plan
documentation says the same about saved plans. TG-P04 comes from the 1.10 and 1.11 release
notes: S3-native locking arrived in 1.10 and `dynamodb_table` was deprecated in 1.11.

**AWS Config managed rules** give TG-P03 and TG-P05, and the optional TG-P10 and TG-P12.
These are AWS's own definitions of what a correctly configured bucket or security group looks
like - `s3-bucket-server-side-encryption-enabled`, `s3-bucket-versioning-enabled`,
`restricted-ssh`, `s3-bucket-logging-enabled`. Using them means the assessment can be checked
against an external reference rather than against my judgement.

**GitHub Actions documentation** gives TG-P06 and TG-P08, from the automatic token
authentication page and the artefact retention behaviour.

The citation lives in the YAML next to the control, and `test_every_control_carries_a_citation_and_remediation`
fails the build if any control loses it.

## The shape of a control

Each entry carries ten fields: id, name, tier, description, evidence source, applicability
condition, decision rule, expected secure result, severity if violated, remediation, source.

The applicability condition earns its place. TG-P05 needs live AWS credentials to read the
bucket's versioning status. Without them the control does not become compliant and does not
become non-compliant - it becomes `indeterminate`, and the run says which evidence was
missing.

## Four outcomes, not two

Most scanners answer pass or fail. This one has four, and the extra two do real work.

`not_applicable` covers controls that do not bear on the configuration under test.

`indeterminate` covers controls that apply but could not be assessed. This is the outcome
that stops the tool producing false assurance. A run that reports seven compliant controls
means one thing when all seven were checked and something quite different when four of them
were never looked at.

Every run therefore reports **assessment coverage**: the share of controls that reached a
definite answer. In the pilot it ranged from 0.12 on a repository-only scenario to 0.88 on
the clean controls. A compliance rate quoted without its coverage is not interpretable, and
the results chapter will always give both.

## Checked against the pilot

Twelve offline observations across six templates:

- Every scenario raised the control its manifest named, and no other control was raised in
  error.
- Four clean-control runs produced zero findings. That figure is the false-alert rate, and it
  matters more than the detection count - a scanner that flags a clean repository is one
  nobody keeps running.
- ST-001 and ST-002 each raised exactly one control and left seven indeterminate, which is
  what should happen when only repository evidence exists.
- WF-001 raised five findings across TG-P06, TG-P07, TG-P08 and TG-P09 from a single
  deliberately bad workflow.

The drift controls - TG-P10, TG-P11, TG-P12 - have not been exercised against real AWS. They
pass against fixtures. That is a weaker claim and the results chapter should say so.

## What was dropped, and what it costs

Checkov was going to run over the same fixtures as an external cross-check. It is now
optional. There is a practical reason as well as an hours one: Checkov pins
`boto3==1.34.25` exactly, which makes the project's dependency set unresolvable, so it needs
its own virtual environment. That is documented in `requirements-checkov.txt`.

The cost is real. Without it the control decisions are checked against documentation but not
against a second implementation, so a systematic misreading of a rule would go unnoticed.
This belongs in threats to validity.
