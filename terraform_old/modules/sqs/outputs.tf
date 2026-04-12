output "aegis_lambda_dlq_arn" {
  value = aws_sqs_queue.aegis_lambda_dlq.arn
}

output "aegis_lambda_dlq_url" {
  value = aws_sqs_queue.aegis_lambda_dlq.id
}
