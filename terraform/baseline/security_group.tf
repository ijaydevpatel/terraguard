# One security group. Secure baseline: administrative access from a single private CIDR.
# Scenario SG-001..SG-00n widen this out-of-band via boto3 to create controlled drift.

data "aws_vpc" "selected" {
  id      = var.vpc_id != "" ? var.vpc_id : null
  default = var.vpc_id == "" ? true : null
}

resource "aws_security_group" "baseline" {
  name        = "${var.name_prefix}-baseline-sg"
  description = "TerraGuard-AI baseline security group"
  vpc_id      = data.aws_vpc.selected.id

  tags = {
    Name           = "${var.name_prefix}-baseline-sg"
    TerraGuardRole = "drift-target"
  }
}

# TG-P10: administrative access restricted to a private range
resource "aws_vpc_security_group_ingress_rule" "ssh_restricted" {
  security_group_id = aws_security_group.baseline.id
  description       = "SSH from the administrative CIDR only"
  cidr_ipv4         = var.admin_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "all_out" {
  security_group_id = aws_security_group.baseline.id
  description       = "Allow all egress"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
