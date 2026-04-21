resource "aws_cloudwatch_event_bus" "bus" {
  name               = "${var.prefix}-${var.event_bus_name}"
  kms_key_identifier = var.kms_key_arn
  description        = var.description

  tags = {
    Name = "${var.prefix}-${var.event_bus_name}"
  }
}
