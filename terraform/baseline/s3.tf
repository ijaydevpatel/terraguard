# Test bucket used as the target for encryption, public-access and logging drift scenarios.

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "test" {
  bucket = "${var.name_prefix}-test-${random_id.suffix.hex}"

  tags = {
    Name           = "${var.name_prefix}-test"
    TerraGuardRole = "drift-target"
    DataClass      = "synthetic"
  }
}

# TG-P03
resource "aws_s3_bucket_server_side_encryption_configuration" "test" {
  bucket = aws_s3_bucket.test.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# TG-P05
resource "aws_s3_bucket_versioning" "test" {
  bucket = aws_s3_bucket.test.id

  versioning_configuration {
    status = "Enabled"
  }
}

# TG-P04
resource "aws_s3_bucket_public_access_block" "test" {
  bucket = aws_s3_bucket.test.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# TG-P12: access logging enabled
resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.name_prefix}-logs-${random_id.suffix.hex}"

  tags = {
    Name      = "${var.name_prefix}-logs"
    DataClass = "synthetic"
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "test" {
  bucket        = aws_s3_bucket.test.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access/"
}
