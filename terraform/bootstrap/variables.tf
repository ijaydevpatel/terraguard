variable "aws_region" {
  description = <<-EOT
    Single region for the whole research environment.

    ap-southeast-2 (Sydney) is chosen over ap-southeast-6 (New Zealand, launched
    September 2025) for service maturity and breadth: Sydney has the longer service
    catalogue and the deeper body of documentation, which matters more for a research
    prototype than the ~25 ms of latency saved. Recorded as a deliberate choice rather
    than a default.
  EOT
  type        = string
  default     = "ap-southeast-2"
}

variable "state_bucket_name" {
  description = "Globally unique name for the Terraform state bucket."
  type        = string
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
