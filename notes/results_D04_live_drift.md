# D04b - The first live drift detection

14 October 2026, run id SG-001-live, account configured in us-east-1.

This is the only result in the project that comes from a real cloud account rather than a
configuration written to disk. Everything in D04 is synthetic by construction; this is not.

## What happened

The baseline was deployed and confirmed clean: `terraform plan -refresh-only` reported no
differences. An injection script then opened port 22 to `0.0.0.0/0` on the baseline security
group using the AWS API directly, never through Terraform. A refresh-only plan was captured and
handed to the tool.

```
SEVERITY             RULE  CONTROL  RESOURCE                     DETAIL
high_or_critical     2     TG-P10   aws_security_group.baseline  ingress.0.cidr_blocks.0: restricted -> public
non_security_or_low  5     -        aws_security_group.baseline  ingress.0.description: value -> absent
non_security_or_low  5     -        aws_security_group.baseline  ingress.1.description: absent -> value
non_security_or_low  5     -        aws_security_group.baseline  ingress.1.from_port: absent -> numeric
non_security_or_low  5     -        aws_security_group.baseline  ingress.1.protocol: absent -> value
non_security_or_low  5     -        aws_security_group.baseline  ingress.1.self: absent -> disabled
non_security_or_low  5     -        aws_security_group.baseline  ingress.1.to_port: absent -> numeric

7 finding(s): 1 high/critical, 0 medium, 6 non-security/low
assessment coverage 0.31
warning: 9 control(s) could not be assessed
FAIL: 1 finding(s) at or above high
exit code 1
```

The change was detected, mapped to TG-P10, placed in the high or critical band by rule 2, and
the gate failed the run. That is the full chain working against infrastructure that existed.

## The six extra findings, and why they are the interesting part

Six of the seven findings are noise, and no synthetic fixture in the corpus ever produced them.

The configuration manages ingress with discrete `aws_vpc_security_group_ingress_rule`
resources, which was a recorded decision taken specifically so that one changed rule produces
one unambiguous attribute path. That part worked as intended. What the decision did not
anticipate is that the parent `aws_security_group` resource still exposes `ingress` as a
computed list. Adding a rule through the API lengthens and reorders that list, so the refresh
reports index-shifted changes across it: a description that moved from index 0 to index 1 looks
like one attribute disappearing and six others appearing.

So the ratio on real data is one true finding to six artefacts, against one to zero on every
synthetic equivalent. A reader of D04 alone would have no reason to expect that.

**The severity ladder contained it.** All six were classified non-security by rule 5, the gate
fired on exactly the right finding, and the exit code was correct. The noise degraded
readability, not the decision. That is the distinction worth making: the tool was right, and
the report was cluttered.

## What this does and does not establish

It establishes that the detection path works end to end outside a fixture: real API change,
real refresh, correct control, correct band, correct exit code.

It does not establish a detection rate. This is one scenario, one run. The five remaining
injection scripts have not been run against the account, so the drift half of the dataset is
still almost entirely synthetic, and D04's figures should continue to be read that way.

It also suggests a measurement the project has not made: signal to noise on real plan output.
Every figure in D04 is computed over scenarios where the expected finding is the only finding.
A real deployment produces a longer, messier list, and nothing in this project measures how
much.
