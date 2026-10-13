variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "terraguard"
}

variable "environment" {
  description = <<-EOT
    Feeds the `environment` ML feature and the blast-radius estimate.
    Only ever deploy with "test"; "production" is a label used by scenario
    variations to study whether severity ranking shifts with environment.
  EOT
  type        = string
  default     = "test"

  validation {
    condition     = contains(["test", "production"], var.environment)
    error_message = "environment must be either test or production."
  }
}

variable "vpc_id" {
  description = "VPC to attach the baseline security group to. Empty means use the default VPC."
  type        = string
  default     = ""
}

variable "admin_cidr" {
  description = "The single CIDR allowed administrative access in the secure baseline."
  type        = string
  default     = "10.0.0.0/8"

  validation {
    condition     = var.admin_cidr != "0.0.0.0/0"
    error_message = "admin_cidr must never be 0.0.0.0/0 in the secure baseline."
  }
}
