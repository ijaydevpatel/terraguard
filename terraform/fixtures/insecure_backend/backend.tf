# Violates TG-P02 (local backend) and TG-P03 (no encryption asserted).
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
