# One role and one narrowly scoped policy. Scenario IAM-001 widens the action to "*"
# out-of-band; IAM-002 widens the trust relationship.

data "aws_iam_policy_document" "assume" {
  statement {
    sid     = "AllowEc2ServiceOnly"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "baseline" {
  name               = "${var.name_prefix}-baseline-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = {
    TerraGuardRole = "drift-target"
  }
}

# TG-P11: explicit actions on explicit resources. No wildcards on either side.
data "aws_iam_policy_document" "baseline" {
  statement {
    sid    = "ReadOnlyOnTestBucketPrefix"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      aws_s3_bucket.test.arn,
      "${aws_s3_bucket.test.arn}/allowed/*",
    ]
  }
}

resource "aws_iam_policy" "baseline" {
  name        = "${var.name_prefix}-baseline-policy"
  description = "Least-privilege read access to the TerraGuard test bucket prefix"
  policy      = data.aws_iam_policy_document.baseline.json
}

resource "aws_iam_role_policy_attachment" "baseline" {
  role       = aws_iam_role.baseline.name
  policy_arn = aws_iam_policy.baseline.arn
}
