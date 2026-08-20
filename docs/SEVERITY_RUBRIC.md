# Severity labelling rubric

Severity is the one thing in this project a machine cannot settle. Drift either appears in
`resource_drift` or it does not. A control is either violated or it is not. But whether an
open port matters more than a disabled trail is a judgement, and judgement needs written
criteria or it drifts between Monday and Thursday.

This rubric exists so that the same finding gets the same label twice, and so that a
reviewer can disagree with a specific rule rather than with a general impression.

## Three classes

Five classes were the original plan. With 60 to 100 observations there are not enough
independent examples to support five, so the primary scheme is three. Five is only revisited
if the class-count gate (T070) shows enough examples per class.

| Class | Meaning |
|---|---|
| **High or critical** | An attacker who found this could reach data or widen access without needing anything else |
| **Medium** | Real weakening of the posture, but exploitation needs another failure first |
| **Non-security or low** | The configuration changed; the security position did not |

## How to decide

Work down the list. Stop at the first rule that applies.

**1. Does it expose data or credentials directly?**
State file committed, secret printed to a job log, plan artefact published, encryption
removed from a bucket holding real data. → **High or critical.**

**2. Does it grant access to someone who did not have it?**
Administrative port open to `0.0.0.0/0` or `::/0`, IAM action or resource widened to `*`,
trust policy widened to a broader principal, public access block disabled on a bucket whose
policy already permits reads. → **High or critical.**

**3. Does it remove the ability to detect or recover?**
CloudTrail stopped, S3 access logging switched off, bucket versioning suspended, log file
validation disabled. → **High or critical** if the control was the only one of its kind,
**medium** if another control still covers the same ground.

**4. Does it weaken a defence that is not the last one?**
Deprecated locking still functioning, TLS-only policy removed while the bucket stays
private, over-broad `GITHUB_TOKEN` on a workflow that only reads. → **Medium.**

**5. Would a security reviewer care at all?**
Tag values, descriptions, names, resource ordering. → **Non-security or low.**

## Rules that override the ladder

**Direction matters.** A change that improves the posture is never a finding. Closing a CIDR
or enabling encryption produces no record at all, so it never reaches this rubric.

**Deletion outside Terraform is high or critical regardless of what was deleted.** Not
because the resource mattered, but because the state file and reality have diverged and
nobody knows what else changed in the same session.

**Environment does not change the class.** A production label may change what you do about a
finding; it does not change what the finding is. Environment is a feature the models can use,
not a thumb on the label.

**Missing evidence is not low severity.** If a control could not be assessed, the outcome is
`indeterminate` and no severity is assigned. Recording "low" because nothing was found is the
mistake this whole design exists to avoid.

## Worked examples

| Finding | Rule | Class |
|---|---|---|
| `cidr_ipv4` moves from `10.0.0.0/8` to `0.0.0.0/0` on port 22 | 2 | High or critical |
| `terraform.tfstate` tracked in the repository | 1 | High or critical |
| Saved plan uploaded by `actions/upload-artifact` | 1 | High or critical |
| CloudTrail `enable_logging` true → false | 3, sole control | High or critical |
| S3 access logging off while CloudTrail still running | 3, other cover | Medium |
| Backend still using `dynamodb_table` | 4 | Medium |
| No `permissions:` block on a read-only workflow | 4 | Medium |
| `tags.Owner` changes from `research` to `research-team` | 5 | Non-security or low |

## Recording a decision

Every label needs the rule number that produced it. When a finding does not fit any rule
cleanly, label it, write down why, and add it to the review sample. Disagreements go in
`datasets/label_disagreements.csv` with the original label, the reviewer's label and the
decision taken. Disagreement is data about how hard the judgement is, not a defect to hide.

## Reviewer instructions

Take a sample that includes every class and every scenario group. Read the finding and the
rule number, not the label. Two questions:

1. Does the rule cited actually apply to this finding?
2. Is there an earlier rule that should have caught it first?

Where you disagree, say which rule you would have used. That is more useful than a different
class, because it says whether the rubric is wrong or only the application of it.
