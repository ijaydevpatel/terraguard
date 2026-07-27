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
