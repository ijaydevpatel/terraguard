# Filled in from the bootstrap stack's `backend_block` output.
# TG-P02: remote, encrypted, locked. Never a local backend.
terraform {
  backend "s3" {
    bucket = "terraguard-state-jp-7f3a21"
    key    = "baseline/terraform.tfstate"
    region = "us-east-1"

    encrypt = true

    # S3-native state locking (Terraform >= 1.11). Replaces the deprecated
    # dynamodb_table argument, which HashiCorp will remove in a future minor version.
    use_lockfile = true
  }
}
