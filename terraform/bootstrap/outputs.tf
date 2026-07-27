output "state_bucket" {
  description = "Name of the state bucket; paste into terraform/baseline/backend.tf."
  value       = aws_s3_bucket.state.id
}

output "lock_table" {
  description = "Name of the DynamoDB lock table."
  value       = aws_dynamodb_table.locks.name
}

output "backend_block" {
  description = "Ready-made backend configuration for the baseline stack."
  value       = <<-EOT
    terraform {
      backend "s3" {
        bucket         = "${aws_s3_bucket.state.id}"
        key            = "baseline/terraform.tfstate"
        region         = "${var.aws_region}"
        encrypt        = true
        dynamodb_table = "${aws_dynamodb_table.locks.name}"
      }
    }
  EOT
}
