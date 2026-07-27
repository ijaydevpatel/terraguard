# GitHub Actions authentication without long-lived credentials.
# This is the control TG-P09 asserts and the insecure_workflow fixture violates.
#
# The CI role is read-only on purpose: the pipeline runs `plan -refresh-only`, never `apply`.

data "aws_iam_policy_document" "github_assume" {
  count = var.github_repository == "" ? 0 : 1

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Scoped to one repository and one branch. Widening this is scenario WF-002.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_openid_connect_provider" "github" {
  count = var.github_repository == "" ? 0 : 1

  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_ci" {
  count = var.github_repository == "" ? 0 : 1

  name               = "terraguard-ci"
  description        = "Read-only role assumed by GitHub Actions via OIDC for refresh-only planning"
  assume_role_policy = data.aws_iam_policy_document.github_assume[0].json
}

data "aws_iam_policy_document" "github_ci_readonly" {
  statement {
    sid    = "ReadInfrastructureStateForDriftDetection"
    effect = "Allow"

    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeVpcs",
      "ec2:DescribeTags",
      "s3:GetBucketVersioning",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicy",
      "s3:GetBucketLogging",
      "s3:GetBucketTagging",
      "s3:GetEncryptionConfiguration",
      "s3:ListBucket",
      "iam:GetRole",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListAttachedRolePolicies",
      "cloudtrail:GetTrail",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTrails",
      "dynamodb:DescribeTable",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "ReadAndLockTerraformState"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]

    resources = ["arn:aws:s3:::${var.state_bucket_name}/*"]
  }

  statement {
    sid       = "StateLocking"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.locks.arn]
  }
}

resource "aws_iam_role_policy" "github_ci" {
  count = var.github_repository == "" ? 0 : 1

  name   = "terraguard-ci-readonly"
  role   = aws_iam_role.github_ci[0].id
  policy = data.aws_iam_policy_document.github_ci_readonly.json
}
