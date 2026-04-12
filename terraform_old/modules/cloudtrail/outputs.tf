output "cloudtrail_trail_name" {
  value = aws_cloudtrail.aegis.name
}

output "cloudtrail_trail_arn" {
  value = aws_cloudtrail.aegis.arn
}

output "cloudtrail_s3_bucket_name" {
  value = aws_cloudtrail.aegis.s3_bucket_name
}

output "cloudtrail_s3_key_prefix" {
  value = aws_cloudtrail.aegis.s3_key_prefix
}

output "cloudtrail_kms_key_id" {
  value = aws_cloudtrail.aegis.kms_key_id
}
