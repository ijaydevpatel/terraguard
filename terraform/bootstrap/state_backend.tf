# Bootstrap: the encrypted, versioned, private S3 backend that TG-P02..TG-P05 assert.
# Apply this once with local state, then migrate: terraform init -migrate-state.

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket_name

  # This bucket holds Terraform state. Deleting it by accident loses the environment.
  lifecycle {
    prevent_destroy = false # research environment; set true for anything real
  }
}

# TG-P05: versioning enabled
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# TG-P03: encryption at rest enabled
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# TG-P04: all four public-access controls blocked
resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# TG-P02: refuse unencrypted transport to the state bucket
resource "aws_s3_bucket_policy" "state_tls_only" {
  bucket = aws_s3_bucket.state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.state.arn,
          "${aws_s3_bucket.state.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# No DynamoDB lock table.
#
# Terraform 1.10 introduced S3-native state locking via `use_lockfile`, which takes the lock
# with an S3 conditional write (If-None-Match) instead of a separate table. Terraform 1.11
# deprecated the `dynamodb_table` backend argument, and it will be removed in a future minor
# version. Using the native lock removes a whole resource, its IAM surface and its cost from
# the research environment, and keeps the backend on a supported path for the life of the
# project. Locking is enabled in the backend block, not here - see outputs.tf.
