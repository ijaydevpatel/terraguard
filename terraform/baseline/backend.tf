# Filled in from the bootstrap stack's `backend_block` output.
# TG-P02: remote, encrypted, locked. Never a local backend.
terraform {
  backend "s3" {
    bucket         = "REPLACE_WITH_BOOTSTRAP_OUTPUT"
    key            = "baseline/terraform.tfstate"
    region         = "eu-west-2"
    encrypt        = true
    dynamodb_table = "terraguard-tf-locks"
  }
}
