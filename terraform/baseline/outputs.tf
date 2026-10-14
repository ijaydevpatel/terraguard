# Nothing sensitive is emitted. TG-P06 is enforced here by omission:
# no credential, no policy document body, no bucket policy is ever output.

output "security_group_id" {
  description = "Baseline security group id (drift target for SG scenarios)."
  value       = aws_security_group.baseline.id
}

output "test_bucket" {
  description = "Baseline test bucket name (drift target for S3 scenarios)."
  value       = aws_s3_bucket.test.id
}

output "log_bucket" {
  description = "Access-log bucket name (drift target for DEL-001)."
  value       = aws_s3_bucket.access_logs.id
}

output "iam_role_name" {
  description = "Baseline IAM role name (drift target for IAM scenarios)."
  value       = aws_iam_role.baseline.name
}

output "iam_policy_arn" {
  description = "Baseline IAM policy ARN (drift target for IAM scenarios)."
  value       = aws_iam_policy.baseline.arn
}

output "cloudtrail_name" {
  description = "Baseline CloudTrail name (drift target for logging scenarios)."
  value       = aws_cloudtrail.baseline.name
}

output "environment" {
  description = "Environment label carried into the ML feature set."
  value       = var.environment
}
