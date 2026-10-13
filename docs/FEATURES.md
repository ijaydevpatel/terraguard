# What TerraGuard-AI does

The complete capability list, each entry tied to the control it assesses, the research
question it serves and the module that implements it. Kept current so the report and the
code cannot drift apart.

Status key: **built** = implemented and tested · **fixture-only** = works against fixtures,
never run against real AWS · **not built** = planned, still a stub.

---

## 1. Infrastructure drift detection

Answers RQ1. Evidence source: Terraform plan JSON.

| Capability | Module | Status |
|---|---|---|
| Read `resource_drift` and `resource_changes` as separate collections | `plan_parser.py` | built |
| Carry `is_remote_drift` so out-of-band change is never confused with a source edit | `plan_parser.py` | built |
| Recognise replacement from the action pair, not the first element | `plan_parser.py` | built |
| Drop no-ops and data reads before they reach the dataset | `plan_parser.py` | built |
| Flatten nested attributes to indexed paths (`ingress.1.cidr_ipv4`) | `drift_extractor.py` | built |
| Categorise values: public, restricted, enabled, disabled, wildcard, sensitive | `drift_extractor.py` | built |
| Redact sensitive values inside the diff itself | `drift_extractor.py` | built |
| Map a diff to a security event, applying direction | `drift_normaliser.py` | built |
| Treat a repair as a non-event (public → restricted raises nothing) | `drift_normaliser.py` | built |
| Out-of-band deletion short-circuits attribute analysis | `drift_normaliser.py` | built |

Six normalised events: public network access, privilege expansion, encryption disabled,
security logging disabled, out-of-band deletion, non-security operational drift. Plus
sensitive data exposure and insecure state handling from the scanners.

---

## 2. Sensitive data exposure

Answers RQ1 and RQ3. This is the half of the project that is not about drift, and it is what
your §2.4 means by treating state as a data-lifecycle problem.

### 2.1 Files that carry secrets

| Detection | Control | Status |
|---|---|---|
| `.tfstate` committed | TG-P01 | built |
| `.tfstate.backup` and numbered backups | TG-P01 | built |
| Saved binary plan (`tfplan`) | TG-P07 | built |
| State-derived `plan.json` / `tfplan.json` | TG-P07 | built |
| **Searches git history, not just the working tree** | TG-P01 | built |
| Distinguishes history-only files from currently tracked ones | TG-P01 | built |

Deleting a state file in a later commit does not remove it from the repository. The scanner
reports those separately so the remediation is different: purge history, not just delete.

### 2.2 Secrets inside files

| Detection | Control | Status |
|---|---|---|
| AWS access key id (`AKIA`/`ASIA`) | TG-P06 | built |
| PEM private key block | TG-P06 | built |
| GitHub token (`ghp_`, `gho_`, …) | TG-P06 | built |
| **Value under a sensitive key name** - `password`, `secret`, `token`, `api_key`, `client_secret`, `connection_string` … | TG-P06 | built |
| Suppresses variable references, placeholders and dummies (`var.pw`, `REPLACE_ME`, `YOUR_KEY`, `null`) | TG-P06 | built |
| Reports the key name and a character count, never the value | TG-P06 | built |

The key-name rule matters because shape-based patterns only catch credentials that look like
credentials. `"password": "hunter2"` has no recognisable shape, and state files are full of
exactly that.

### 2.3 Leftover working files

| Detection | Control | Status |
|---|---|---|
| `.tfstate.tmp` / `.old` / `.orig` / `.save` / `.swp` | TG-P01 | built |
| Numbered state copies (`terraform.tfstate.1`) | TG-P01 | built |
| Plan output captured to `plan.out` / `tfplan.log` | TG-P01 | built |
| State cached under `.terraform/` | TG-P01 | built |
| `crash.log` (can contain state values) | TG-P01 | built |

Covers the temporary-file and deletion part of the lifecycle: a state file removed from its
normal path often survives somewhere else.

### 2.4 Redaction before anything is written

| Capability | Module | Status |
|---|---|---|
| Honour the plan's `before_sensitive` / `after_sensitive` trees | `redactor.py` | built |
| Key-name and value-shape heuristics on top, because provider flags are inconsistent | `redactor.py` | built |
| Shape-preserving replacement `[REDACTED]:len=n:sha256:…` | `redactor.py` | built |
| Binary plan and raw JSON deleted in a `finally` block | `evidence_collector.py` | built |
| `assert_clean()` as a final gate before output | `redactor.py` | built |
| Sanitised terminal / JSON / CSV report | `report_generator.py` | built |

Verified on real data: 12 pilot runs over fixtures containing `TERRAGUARD_TEST_SECRET`
markers produced zero markers in any output file.

---

## 3. CI/CD workflow security

Answers RQ1 and RQ4. Evidence source: GitHub Actions workflow YAML.

| Detection | Control | Status |
|---|---|---|
| Saved plan or state uploaded via `actions/upload-artifact` | TG-P07 | built |
| State or plan paths written to `actions/cache` | TG-P07 | built |
| Plan contents echoed to the job log (`cat tfplan.json`) | TG-P06 | built |
| No `permissions:` block - token falls back to the repository default | TG-P08 | built |
| `permissions: write-all` / `read-all` | TG-P08 | built |
| Long-lived `AWS_ACCESS_KEY_ID` instead of OIDC | TG-P09 (optional) | built |
| Unparseable workflow reported rather than skipped | TG-P08 | built |

---

## 4. Backend and state storage

| Detection | Control | Status |
|---|---|---|
| Local backend, or no backend block at all | TG-P02 | built |
| `encrypt` not set to true | TG-P03 | built |
| No state locking configured | TG-P04 | built |
| Deprecated `dynamodb_table` locking | TG-P04 | built |
| Static parse works with no AWS credentials | - | built |
| Live bucket encryption / versioning / public-access block via boto3 | TG-P03, TG-P05, TG-P02 | fixture-only |

---

## 5. Policy control assessment

Answers RQ3. Eight core controls, four optional, each with a citation and remediation.

| Capability | Status |
|---|---|
| Four outcomes: compliant, non-compliant, not applicable, **indeterminate** | built |
| Missing or unreadable evidence returns indeterminate, never compliant | built |
| Assessment coverage reported with every run | built |
| Optional controls excluded unless explicitly requested | built |
| Duplicate control ids rejected at load time | built |
| Every control cites HashiCorp, AWS Config or GitHub Actions documentation | built |

Coverage is the guard against false assurance. A compliance rate quoted without it cannot be
interpreted - in the pilot, coverage ran from 0.12 on a repository-only scenario to 0.88 on
the clean controls.

---

## 6. Severity prioritisation

Answers RQ2. Comparator, features, both models and the predictor are built.

| Capability | Module | Status |
|---|---|---|
| Written labelling rubric, three classes, five-rule ladder | `docs/SEVERITY_RUBRIC.md` | built |
| Deterministic severity table (the non-AI comparator) | `severity_rules.py` | built |
| Feature encoding | `feature_builder.py` | built |
| Logistic Regression | `model_trainer.py` | built |
| Random Forest | `model_trainer.py` | built |
| `StratifiedGroupKFold` grouped by scenario template | `model_trainer.py` | built |
| Rank a live finding with a confidence | `model_predictor.py` | built |

The models rank findings that deterministic logic has already established. They never decide
whether drift exists or whether a control was violated.

`severity_rules.py` was frozen before any model is trained, and every label it returns carries
the number of the rule that produced it. If Logistic Regression and Random Forest cannot beat a
lookup table, that is a reportable result rather than an awkward one - but only because the
table was fixed first.

---

## 7. Experiment and evidence generation

Answers RQ1 and RQ4.

| Capability | Status |
|---|---|
| Run Terraform init / validate / `plan -refresh-only` / `show -json` | built |
| Offline path from an existing plan JSON, no credentials needed | built |
| Repository, workflow and backend evidence capture | built |
| 19 core scenario templates with ground-truth manifests written before any run | built |
| Seven out-of-band injection scripts with baseline pre-flight checks | fixture-only |
| Baseline restore with a zero-drift confirmation | fixture-only |
| Experiment harness writing `observations.csv` and `findings.csv` | built |
| Manifest read once, then set aside until the row is written | built |
| Processing time captured per run | built |
| Drift scenario with no plan JSON fails loudly instead of writing an empty row | built |

---

## 8. Reporting and CI/CD gating

| Capability | Status |
|---|---|
| `terraguard collect` | built |
| `scan`, `analyse`, `train`, `evaluate`, `report` subcommands | built |
| Terminal, JSON and CSV sanitised reports | built |
| Severity gate: critical/high fail, medium warn, low pass, indeterminate warn | built |
| Three recorded GitHub Actions runs | **not built** |

---

## Explicitly out of scope

Multi-cloud. Large language models. Autonomous remediation. Production deployment. Formal
regulatory certification. Web dashboard. These are stated exclusions in §1.4, not a backlog.

---

## Detection defects found and fixed by the generated corpus

| Defect | Effect before the fix |
|---|---|
| Drift findings carried no control id | TG-P10/P11/P12 could never be non-compliant; an open security group assessed as compliant |
| No control covered out-of-band deletion | A deleted resource was detected, then assessed as compliant. TG-P13 added |
| Encryption removal categorised as a value change | Turning encryption off produced no finding |
| Public access block off read as housekeeping | Classified as non-security operational drift |
| `id-token: write` reported as a leaked secret | False positive on the project's own secure workflow fixture |

## Honest status, 14 October 2026

Detection, policy assessment and the deterministic severity baseline are built and tested.
The models and the reporting layer are not.

The dataset is now trainable, but only on its offline half. 26 observations and 32 findings
have been collected across 13 templates, and every severity class has at least three
independent scenario groups, so a group-aware cross-validation is feasible. The nine AWS drift
templates have produced nothing at all, because the baseline has never been deployed.

That is still the single largest gap between what this document claims and what has been
demonstrated. Infrastructure drift is the project's headline claim, and every drift capability
listed above has been exercised against fixtures only. Until T021 puts the baseline into a real
account, the drift half of RQ1 rests on synthetic evidence.
