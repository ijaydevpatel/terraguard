variable "aws_region" {
  description = "Single region for the whole research environment."
  type        = string
  default     = "eu-west-2"
}

variable "state_bucket_name" {
  description = "Globally unique name for the Terraform state bucket."
  type        = string
}

variable "lock_table_name" {
  description = "DynamoDB table used for state locking."
  type        = string
  default     = "terraguard-tf-locks"
}
