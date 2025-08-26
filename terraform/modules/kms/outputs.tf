output "central_logs_key_arn" {
  value = aws_kms_key.central_logs_key.arn
}

output "central_logs_key_id" {
  value = aws_kms_key.central_logs_key.key_id
}

output "central_logs_alias_arn" {
  value = aws_kms_alias.central_logs_key_alias.arn
}
