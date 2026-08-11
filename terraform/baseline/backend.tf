# Filled in from the bootstrap stack's `backend_block` output.
# TG-P02: remote, encrypted, locked. Never a local backend.
terraform {
  backend "s3" {
    bucket = "REPLACE_WITH_BOOTSTRAP_OUTPUT"
    key    = "baseline/terraform.tfstate"
    region = "ap-southeast-2"

    encrypt = true

    # S3-native state locking (Terraform >= 1.11). Replaces the deprecated
    # dynamodb_table argument, which HashiCorp will remove in a future minor version.
    use_lockfile = true
  }
}
