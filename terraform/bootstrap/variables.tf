variable "aws_region" {
  description = "Single region for the whole research environment."
  type        = string
  default     = "eu-west-2"
}

variable "state_bucket_name" {
  description = "Globally unique name for the Terraform state bucket."
  type        = string
}

variable "lock_table_name" {
  description = "DynamoDB table used for state locking."
  type        = string
  default     = "terraguard-tf-locks"
}

variable "budget_alert_email" {
  description = "Where AWS Budgets sends the $5 and $15 alerts."
  type        = string
}

variable "github_repository" {
  description = <<-EOT
    owner/repo for the GitHub Actions OIDC trust policy, e.g. "dhruvi/terraguard-ai".
    Leave empty to skip creating the OIDC provider and CI role until Phase 9.
  EOT
  type        = string
  default     = ""
}
