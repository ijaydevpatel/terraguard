# Deprecated DynamoDB locking. Still functioning, but on a path HashiCorp will remove.
# Rule 4: a defence weakened, not the last one.
terraform {
  backend "s3" {
    bucket         = "terraguard-state-example-0001"
    key            = "baseline/terraform.tfstate"
    region         = "ap-southeast-2"
    encrypt        = true
    dynamodb_table = "terraguard-tf-locks"
  }
}
