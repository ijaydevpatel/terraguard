# Design decisions log

Append-only. Every entry here becomes a paragraph in the methodology or discussion chapter.
Record the decision, the alternatives considered, and why the alternative lost.

---

## 2026-07-28 — P0/P1 foundations

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

## 2026-07-28 — CI, first run

**Checkov is installed in its own virtual environment, not in `requirements-dev.txt`.**
Alternative: keep it in the dev requirements and loosen the project's `boto3` pin to
accommodate it. Rejected because checkov 3.2.200 pins `boto3==1.34.25` exactly, so pip's
resolver fails outright (`ResolutionImpossible`) — which is how the first CI run failed after
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

## 2026-07-28 — supervisor review response

**State locking moved from DynamoDB to S3-native `use_lockfile`.**
Alternative: keep the DynamoDB lock table. Rejected because Terraform 1.10 introduced
S3-native locking through a conditional write, and 1.11 deprecated the `dynamodb_table`
backend argument, which HashiCorp will remove in a future minor version. Building a
research prototype on a deprecated path would age badly across the life of the project.
The native lock also removes a resource, its IAM surface and its cost from the environment.
Terraform floor raised from 1.7 to **1.11**.
Evidence: `terraform/bootstrap/state_backend.tf`, `outputs.tf`, `terraform/baseline/backend.tf`.

**`ap-southeast-2` (Sydney) retained even though a New Zealand region now exists.**
AWS opened `ap-southeast-6` (Auckland) on 2 September 2025, so the earlier justification —
"nearest mainstream region" — was wrong. Sydney is kept on different grounds: broader service
catalogue and substantially more documentation, which outweighs the latency saving for a
prototype. The point is that the region is now a recorded decision with a stated reason,
not an unexamined default.
Evidence: `terraform/bootstrap/variables.tf`, `docs/AWS_SETUP.md`.

**Scope reduced from a 424 h plan to a 101 h plan.**
The original estimate was roughly four times the scale agreed for a STEM research project.
Re-baselining exposed an inconsistency worth recording: P0 and P1 had been estimated at 70 h,
which would have consumed 70% of a 100 h budget on scaffolding. Every estimate was rescaled,
including retrospectively — P0/P1 is now 18 h, which reflects what was actually built.
Scope cuts: 12 controls to 8, 20-30 scenario templates to 10-12, 200-300 observations to
60-100, five severity classes to three, four report formats to two (terminal and JSON), and
the Checkov comparison and TerraDS robustness pass dropped unless the freeze is met early.
Consequence: 83 h remain across ~11.5 weeks, about 7 h/week. Time is no longer the binding
constraint — AWS availability and the wall-clock duration of the experiment runs are.

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
## YYYY-MM-DD — <phase / task id>

**<Decision in one sentence.>**
Alternative: <what else was considered>. Rejected because <reason>.
Evidence: <file, test, or report artefact that shows it>.
```
