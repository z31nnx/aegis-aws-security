output "aegis_key_arn" {
  value = aws_kms_key.aegis_key.arn
}

output "aegis_key_id" {
  value = aws_kms_key.aegis_key.key_id
}

output "aegis_key_alias_arn" {
  value = aws_kms_alias.aegis_key_alias.arn
}
