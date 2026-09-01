terraform {
  backend "s3" {
    bucket         = "terraguard-state-example-0001"
    key            = "baseline/terraform.tfstate"
    region         = "ap-southeast-2"
    encrypt      = true
    use_lockfile = true
  }
}
