provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "TerraGuard-AI"
      Environment = "research"
      ManagedBy   = "terraform"
      Component   = "state-backend-bootstrap"
    }
  }
}

# AWS Budgets is a global service that only answers in us-east-1, regardless of the
# region everything else is deployed in.
provider "aws" {
  alias  = "global"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "TerraGuard-AI"
      Environment = "research"
      ManagedBy   = "terraform"
      Component   = "cost-guardrails"
    }
  }
}
