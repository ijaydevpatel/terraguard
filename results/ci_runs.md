# CI gate runs, artefact check and timing (T099, T100, T102)

Recorded on GitHub Actions on 17 October 2026, workflow `terraguard`, started by hand with the
`target` input at commit 819a456. Ubuntu runner, Python 3.12, `pip install -e .`.

## The three runs

| Run | Target | Findings in report | Status | Severity gate step | Job | Whole run |
|---|---|---|---|---:|---:|---:|
| #3 | `terraform/fixtures/clean` | none | success | 1 s | 18 s | 23 s |
| #4 | `terraform/fixtures/bk_002_deprecated_lock` | 1 medium (TG-P04) | success, with a warning | 0 s | 15 s | 18 s |
| #5 | `terraform/fixtures/exposed_state` | 3 high/critical (TG-P01 twice, TG-P07) | failure, exit code 1 | 0 s | 17 s | 21 s |

Each outcome is the one the gate is designed to give: low or nothing passes, medium warns and
passes, high or critical fails the build. The failure in run #5 is the intended result. The
drift job was skipped in all three because the `AWS_ROLE_ARN` repository variable is not set.

## No secret in any CI artefact

Each run uploads one artefact, `terraguard-report.json`. All three were downloaded and checked:

| Check | #3 | #4 | #5 |
|---|---|---|---|
| AWS key, private key or GitHub token shape | none | none | none |
| Value under a sensitive key name | none | none | none |
| Any of the 17 string values in the three fixtures | none | none | none |
| Synthetic secret markers `TERRAGUARD_TEST_SECRET_001` to `_003` | 0 | 0 | 0 |

Run #5 is the meaningful one. Its target holds a state file, a state backup and a saved plan
that between them carry three synthetic secrets. The report names all three files and raises
the right controls, and contains none of the three values.

## Local against CI

| | Local (Windows, `results/gate_runs.md`) | CI (Ubuntu runner) |
|---|---:|---:|
| Gate on one fixture, interpreter start included | 0.75 to 0.83 s | 0 to 1 s (GitHub reports whole seconds) |
| Everything else in the job | none | 14 to 17 s: checkout, Python setup, package install |
| Analysis of one live plan JSON | 14 to 59 ms | not run in CI |

The analysis itself costs the same in both places, under a second. What CI adds is setting up
the environment, about 15 seconds a run, and that is where any time saving would come from:
caching the installed package rather than making the scan faster. GitHub's one-second step
resolution means the CI gate figure is an upper bound, not a measurement as fine as the local one.
