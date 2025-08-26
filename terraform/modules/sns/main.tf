resource "aws_sns_topic" "high" {
  name = var.sns_alerts_high_topic_name
  tags = var.global_tags
}

resource "aws_sns_topic" "medium" {
  name = var.sns_alerts_medium_topic_name
  tags = var.global_tags
}