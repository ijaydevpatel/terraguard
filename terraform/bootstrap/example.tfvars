# Copy to terraform.tfvars and edit. terraform.tfvars is gitignored.
aws_region        = "eu-west-2"
state_bucket_name = "terraguard-state-CHANGE-ME-0001" # must be globally unique
lock_table_name   = "terraguard-tf-locks"

budget_alert_email = "you@example.com"

# Set once the GitHub repository exists; leave empty until Phase 9.
github_repository = ""
