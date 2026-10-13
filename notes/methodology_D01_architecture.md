# D01 - Architecture and design decisions

Draft for the methodology chapter. Written from `notes/decisions.md`; every claim here
points at a file or a test.

## The problem the design starts from

Terraform already knows when infrastructure has been changed behind its back. Run
`terraform plan -refresh-only` and the JSON output carries a `resource_drift` array listing
what the provider reports versus what state expects. The information is there. What is
missing is any sense of whether a given difference matters.

A tag change and an SSH port opened to the internet appear in that array the same way. An
engineer reading a plan with forty drift entries has no ordering to work with, and the two
that matter sit somewhere in the middle. That gap - detection without prioritisation - is
what this prototype addresses.

## Detection is deterministic; only ranking is learned

The single constraint that shapes everything else: no model output decides whether drift
exists or whether a control was violated.

Drift comes from Terraform's own output. Control violations come from rules in
`policy_engine.py`. The classifiers in Phase 7 only order findings that these deterministic
steps have already established. If a model were allowed to decide that something is drift,
the ground truth would depend on the model, and the evaluation would be circular.

This also makes failure legible. When the tool is wrong about *whether* something happened,
the bug is in a rule and can be found. When it is wrong about *how much it matters*, that is
a ranking error and is measured separately.

## Ten components, and why they are separate

| Component | File | Job |
|---|---|---|
| Evidence collector | `evidence_collector.py` | Run Terraform, capture evidence, destroy the dangerous artefacts |
| Redactor | `redactor.py` | Remove secrets on write |
| Plan parser | `plan_parser.py` | Read `resource_drift` and `resource_changes` |
| Drift extractor | `drift_extractor.py` | Diff before/after into attribute paths |
| Normaliser | `drift_normaliser.py` | Give a diff its security meaning |
| Repository scanner | `repository_scanner.py` | State and plan files in the repo and its history |
| Workflow scanner | `workflow_scanner.py` | CI handling of state, plans and credentials |
| Backend scanner | `backend_scanner.py` | Backend configuration and, where possible, the live bucket |
| Policy engine | `policy_engine.py` | Assess controls against evidence |
| Severity models | Phase 6-7 | Rank findings that already exist |

The split between parser, extractor and normaliser is the one that needed thought. All three
could sit in one module. Keeping them apart means the normalisation table - the part that
encodes security judgement - can be read and argued with on its own, without wading through
JSON handling.

## Four decisions worth defending

### Drift and intentional change are different things

`resource_drift` records what changed in the provider. `resource_changes` records what
Terraform intends to do to reconcile configuration with state. The first is drift; the second
is somebody editing the source.

Every record carries `is_remote_drift`. Conflating them would put deliberate configuration
edits into the drift dataset, and every severity label built on that dataset would be
measuring the wrong thing.

Replacement needed care too. Terraform writes it as a pair - `["delete", "create"]` or
`["create", "delete"]` depending on `create_before_destroy` - so reading the first element
alone misclassifies half of all replacements as deletions. `classify_action` checks the pair.

### Direction decides whether a change is a finding

`restricted → public` is a finding. `public → restricted` is somebody fixing the problem.

Without that rule the dataset fills with findings for changes that improved the security
position, and a classifier trained on it learns that repairs and regressions look alike.
`normalise_attribute` checks both the before and after category, and
`test_closing_a_cidr_is_not_reported` asserts it.

### Redaction happens on write, not at report time

Sanitising at report time means the raw plan JSON sits on disk for the whole run, and every
intermediate file becomes a place a secret can escape from.

Instead the binary plan and raw JSON are written to a `tempfile.mkdtemp` directory and
removed in a `finally` block. Only the redacted copy reaches the output directory.

Redaction keeps the shape of what it removes: values become
`[REDACTED]:len=n:sha256:xxxxxxxxxxxx`. The length and the hash let the feature builder still
compute `sensitive_data_involved`, and let the same secret be recognised across runs, without
the value being recoverable.

Provider sensitivity flags are honoured but not trusted alone. Coverage of the `sensitive`
flag varies between resource types, so a key-name pattern and a value-shape pattern run as
well. A missed secret cannot be un-published.

### Every module runs without credentials

`collect_from_plan_json` builds an evidence bundle from an existing plan JSON. The backend
scanner's default path parses `backend.tf` as text rather than querying S3. The whole
pipeline can be exercised from a committed fixture.

This started as a way to keep CI green without giving GitHub Actions AWS access. It turned
out to matter more than that: the AWS account has been the slowest part of the project, and
Phases 2 to 5 were built and tested while it did not exist.

## Missing evidence is not compliance

The policy engine returns four outcomes. Three are obvious. The fourth, `indeterminate`, is
the one the design turns on.

If a control applies but the evidence needed to assess it was never collected, the engine
says so. It does not return `compliant`. A scanner that treats absent evidence as a pass
produces false assurance, which is worse than no assurance, because somebody acts on it.

The pilot shows the effect. ST-001 gives the engine repository evidence only, so seven of
eight controls come back indeterminate and assessment coverage reads 0.12. The clean-control
runs reach 0.88. Coverage is reported with every run for this reason: a high compliance rate
across a low coverage figure means very little.

## What the design does not do

No web interface. No automatic remediation. No multi-cloud. No language model anywhere in the
pipeline. Single region, single account.

These are not deferred features. A 100-hour project that tried to include them would produce
a shallow version of each, and the question being asked - can drift and state-handling
findings be prioritised usefully - does not need any of them.

## Four outcomes, and when the fourth one became real

The design always specified four policy outcomes. For most of the project only three were
reachable: compliant, non-compliant and indeterminate. `applies_when` was stored as prose and
never evaluated, so a control about IAM read as compliant against a plan containing no IAM at
all. That is false assurance arriving through a different door than the one `indeterminate`
closes, and an external review found it rather than the test suite.

Each control now carries `applies_to`, a list of resource-type prefixes, which is the machine
readable half of `applies_when`. When the caller can enumerate what the target contains, a
control whose subject is absent returns `not_applicable`. When the caller cannot, the control
is assessed as before: a component that does not know the inventory should not be made to
invent one.

The distinction the four outcomes draw is between four different states of knowledge:

| Outcome | Means |
|---|---|
| compliant | the control was assessed and the target satisfies it |
| non_compliant | the control was assessed and the target violates it |
| indeterminate | the control applies but the evidence to judge it was missing or unreadable |
| not_applicable | the control does not bear on this target at all |

Collapsing the last two into `compliant` is the failure this architecture exists to avoid, and
it took a live review to notice that half of it was still theoretical.
