# Copy to terraform.tfvars and edit. terraform.tfvars is gitignored.
aws_region        = "us-east-1"
state_bucket_name = "terraguard-state-CHANGE-ME-0001" # must be globally unique

budget_alert_email = "you@example.com"

# Set once the GitHub repository exists; leave empty until Phase 9.
github_repository = ""
