output "central_logs_bucket_id" {
  value = aws_s3_bucket.central_logs_bucket.id
}

output "central_logs_bucket_arn" {
  value = aws_s3_bucket.central_logs_bucket.arn
}

output "central_logs_bucket_name" {
  value = aws_s3_bucket.central_logs_bucket.bucket
}

output "cloudtrail_logs_prefix" {
  value = "cloudtrail/AWSLogs/${local.account_id}/"
}

output "config_logs_prefix" {
  value = "config/AWSLogs/${local.account_id}/Config/"
}

output "cwl_export_prefix" {
  value = "cwl-export/"
}