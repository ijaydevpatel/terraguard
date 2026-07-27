terraform {
  backend "s3" {
    bucket         = "terraguard-state-example-0001"
    key            = "baseline/terraform.tfstate"
    region         = "eu-west-2"
    encrypt        = true
    dynamodb_table = "terraguard-tf-locks"
  }
}
