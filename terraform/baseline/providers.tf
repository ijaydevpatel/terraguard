provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "TerraGuard-AI"
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "baseline"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
