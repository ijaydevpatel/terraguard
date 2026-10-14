# Checkov comparison

An external cross-check of the control decisions. Every control in this project is traced to
HashiCorp, AWS Config or GitHub Actions documentation, which shows the rules are not invented
but does nothing to catch a systematic misreading of one. A second implementation can.

Checkov 3.3.29, installed in its own virtual environment because it pins boto3 exactly and
cannot share this project's dependency set.

## Results

| Target | Checkov resources | Checkov failed | TerraGuard |
|---|---:|---:|---|
| `bk_001_local_backend` | 0 | 0 | TG-P02 |
| `bk_002_deprecated_lock` | 0 | 0 | TG-P04 |
| `bk_003_no_locking` | 0 | 0 | TG-P04 |
| `clean` | 0 | 0 | none |
| `insecure_backend` | 0 | 0 | TG-P02 |
| `terraform/baseline` | 19 | 20 | none |
| `terraform/bootstrap` | 10 | 6 | TG-P02, TG-P03, TG-P04 |

## The fixtures are not a comparison, and saying so matters

The five backend fixtures show Checkov finding nothing. That is **not agreement**. Each one
contains a `terraform { backend }` block and no resources at all, and Checkov's checks operate
on resource blocks, so `resource_count` is zero and there is nothing for it to evaluate.

Reporting "Checkov: 0 findings, TerraGuard: TG-P02" as a win would be the worst kind of
comparison: technically accurate and completely misleading. The column is included precisely so
the reader can see why the number is zero.

What it does show is a genuine coverage difference. Checkov does not evaluate the backend block
in these files; this project does, and state handling is the gap it was written to fill.

## Where both tools had something to look at

**`terraform/baseline`: Checkov 20 findings, TerraGuard none.**

Expected, and in Checkov's favour on breadth. Its findings are about resources this project
does not govern: access logging on the log bucket itself (CKV_AWS_18), bucket versioning
(CKV_AWS_21), KMS rather than AES256 (CKV_AWS_145), lifecycle configuration (CKV2_AWS_61),
event notifications (CKV2_AWS_62). None of these are among the thirteen controls, which are
scoped to state handling, drift and CI exposure. TerraGuard reporting nothing here is correct
for its scope and silent about everything outside it.

**`terraform/bootstrap`: TerraGuard reports TG-P02, TG-P03 and TG-P04.**

This one is worth stating plainly because it is a false positive of a specific kind. The
bootstrap stack has no remote backend *by design*: it is the stack that creates the state
bucket, so it cannot store its state in a bucket that does not exist yet. That chicken-and-egg
is standard Terraform practice, and the tool flags it as insecure state handling.

A production scanner needs a way to accept this, the same way `.terraguardignore` accepts
documented example secrets. The project does not have a control-level allowlist, so this is
recorded as a known limitation rather than patched late. Suppressing it by special-casing a
directory name would hide the same pattern in someone else's bootstrap stack, which is the one
place it is genuinely common.

## What this does not establish

No precision or recall figure is computed. The two tools answer different questions over
different surfaces, and any such number would compare scope rather than accuracy. Five fixtures
and two stacks is not a corpus.

The honest claim: on the backend controls, Checkov has no overlapping check to disagree with,
so the catalogue remains validated against documentation alone. The comparison's real finding
is a false positive in this project's own bootstrap stack, which the internal fixtures never
surfaced because none of them modelled a stack that legitimately has local state.
