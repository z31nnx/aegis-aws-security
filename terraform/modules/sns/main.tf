resource "aws_sns_topic" "high" {
  name              = "${var.name_prefix}-${var.sns_alerts_high_topic_name}"
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic" "medium" {
  name              = "${var.name_prefix}-${var.sns_alerts_medium_topic_name}"
  kms_master_key_id = var.kms_key_arn
}

resource "aws_sns_topic_subscription" "high_subscriptions" {
  for_each = toset(var.sns_emails)

  topic_arn = aws_sns_topic.high.arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_sns_topic_subscription" "medium_subscriptions" {
  for_each = toset(var.sns_emails)

  topic_arn = aws_sns_topic.medium.arn
  protocol  = "email"
  endpoint  = each.value
}