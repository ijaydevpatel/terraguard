terraform {
  # 1.11 is the floor: S3-native state locking (use_lockfile) is generally available from
  # 1.11, and the dynamodb_table backend argument is deprecated from the same release.
  required_version = ">= 1.11.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.55"
    }
  }
}
