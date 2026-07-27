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

output "github_ci_role_arn" {
  description = "Role ARN for the configure-aws-credentials action. Empty until github_repository is set."
  value       = try(aws_iam_role.github_ci[0].arn, "")
}

output "budget_alerts" {
  description = "Confirmation that both cost guardrails exist."
  value       = "${aws_budgets_budget.early_warning.name}, ${aws_budgets_budget.hard_stop.name}"
}
