# Final gitleaks scan (B03)

17 October 2026, gitleaks 8.30.1, `gitleaks git . --redact` over the full history of the
repository: 51 commits, about 2.4 MB.

## First pass: three findings, all synthetic

| File | Commit | Rule | What the value is |
|---|---|---|---|
| `scripts/demo_leak_prevention.py` line 32 | 16d817b | generic-api-key | AWS's published documentation placeholder secret, planted on purpose by the leak demonstration |
| `scenarios/generate_corpus.py` line 94 | f171cf8 | private-key | a PEM header followed by 40 `x` characters, which is not a usable key |
| `tests/test_scanners.py` line 119 | 0156ebc | generic-api-key | the test string `abcdef123456` for the key-name rule |

Each was checked against the committed source, not just the redacted report.

## Second pass: no leaks found

The three are listed in `.gitleaksignore` by fingerprint, which pins each to one commit and one
line, so a new secret in the same files is still reported. The rescan of the full history
returned no leaks.

A scan of the working folder (`gitleaks dir .`) also reports 45 hits under `corpus/`. That
folder is the generated synthetic corpus: it holds deliberate credential shapes and is
gitignored, so it never reaches the repository.
