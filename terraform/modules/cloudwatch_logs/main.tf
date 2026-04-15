resource "aws_cloudwatch_log_group" "log_group" {
  name = "${var.prefix}-${var.log_group_name}"
  deletion_protection_enabled = var.deletion_protection_enabled
  log_group_class = var.log_group_class
  retention_in_days = var.retention_in_days
  kms_key_id = var.kms_key_arn

  tags = {
    Name = "${var.prefix}-${var.log_group_name}"
  }
}