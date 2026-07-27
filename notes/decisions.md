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

## Template for new entries

```
## YYYY-MM-DD — <phase / task id>

**<Decision in one sentence.>**
Alternative: <what else was considered>. Rejected because <reason>.
Evidence: <file, test, or report artefact that shows it>.
```
