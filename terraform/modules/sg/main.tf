resource "aws_security_group" "quarantine_sg" {
  name                   = "${var.name_prefix}-${var.quarantine_sg_name}-sg"
  description            = "Aegis Quarantine Security Group"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true # Deletes the SG cleanly when you nuke it

  ingress = []
  egress  = []

  tags = {
    Name = "${var.name_prefix}-${var.quarantine_sg_name}"
  }
}