# Sensitive artefact check (T100)

16 October 2026, after the live AWS runs, the fresh-clone check and the three gate runs.

| Check | Result |
|---|---|
| `evidence/` after the live runs | empty: every refresh-only plan JSON was deleted in a `finally` block |
| Saved binary plans on disk | two stale plans from 13 Oct removed (`*.tfplan`, gitignored, never tracked) |
| State or plan files in the tracked tree | none: `check_no_state_files.py` passes on every `git ls-files` path |
| Repository self-scan, `terraguard scan . --fail-on high` | exit 0, no findings |
| AWS access key shapes in datasets, results, notes, docs | none |
| Account id in tracked files | masked as `<account>` in `datasets/injection_runs.jsonl`; `record()` now masks on write |
| Attribute values in `findings.csv` for live runs | none: details carry categories such as `restricted -> public`, never values |
| Leak demonstration | 9/9: a planted key and password are found, never reprinted, and the commit is blocked, including a commit holding only a password |

Two things are outside this check. `build/` holds the experiment logs, which name the IAM
user and account; it is gitignored and stays local. The account id also appears in one
committed version of `injection_runs.jsonl` (commit 00b07c5). An account id is not a
credential, but removing it from published history would need a history rewrite and a force
push, which is the repository owner's decision.

The corpus under `corpus/` holds deliberate credential shapes and state files. It is
generated, synthetic and gitignored.
