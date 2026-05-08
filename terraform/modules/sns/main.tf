resource "aws_sns_topic" "topic" {
  name              = "${var.prefix}-${var.topic_name}"
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "subscription" {
  for_each = toset(var.emails)

  topic_arn = aws_sns_topic.topic.arn
  protocol  = var.protocol
  endpoint  = each.value
}