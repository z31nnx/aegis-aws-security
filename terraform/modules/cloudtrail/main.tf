resource "aws_cloudtrail" "aegis" {
  name                          = "${var.cloudtrail_name}"
  s3_bucket_name                = var.central_logs_bucket_name
  s3_key_prefix                 = "cloudtrail"
  region                        = var.region
  kms_key_id                    = var.central_logs_key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = merge(
    local.global_tags, {
      Name = "${var.cloudtrail_name}"
    }
  )
}
