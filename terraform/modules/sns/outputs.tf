output "sns_alerts_high_topic_arn" {
  value = aws_sns_topic.high.arn
}

output "sns_alerts_medium_topic_arn" {
  value = aws_sns_topic.medium.arn
}