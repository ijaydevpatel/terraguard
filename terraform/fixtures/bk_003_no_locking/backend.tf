# Encrypted and remote, but no locking configured at all.
terraform {
  backend "s3" {
    bucket  = "terraguard-state-example-0001"
    key     = "baseline/terraform.tfstate"
    region  = "ap-southeast-2"
    encrypt = true
  }
}
