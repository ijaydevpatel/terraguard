variable "aws_region" {
  description = <<-EOT
    Single region for the whole research environment.

    us-east-1 is the region the account owner works in. An earlier revision argued for a
    Sydney region on service maturity and latency grounds, but that reasoning never weighed
    who would actually operate the environment, and every AWS step in this project is run by
    hand. A region the operator is set up for beats a marginally better one they are not.

    Recorded as a deliberate choice rather than a default. The limitations section should say
    the experiment ran in a single region, without claiming the region was selected on
    technical grounds.
  EOT
  type        = string
  default     = "us-east-1"
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
