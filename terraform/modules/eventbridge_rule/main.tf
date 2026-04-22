resource "aws_cloudwatch_event_rule" "event_rule" {
  name           = "${var.prefix}-${var.rule_name}"
  description    = var.description
  state          = var.state
  event_bus_name = try(var.event_bus_name, null)
  event_pattern  = var.event_pattern

  tags = {
    Name = "${var.prefix}-${var.rule_name}"
  }
}

resource "aws_cloudwatch_event_target" "event_target" {
  rule           = aws_cloudwatch_event_rule.event_rule.name
  event_bus_name = try(var.event_bus_name, null)
  target_id      = var.target_id
  arn            = var.target_arn
}