resource "aws_cloudtrail" "aegis" {
  name                          = "${var.name_prefix}-${var.cloudtrail_name}"
  s3_bucket_name                = var.central_logs_bucket_name
  s3_key_prefix                 = "cloudtrail"
  region                        = var.region
  kms_key_id                    = var.central_logs_key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = {
    Name = "${var.name_prefix}-${var.cloudtrail_name}"
  }

  lifecycle {
    ignore_changes = [
      tags["Aegis:Status"],
      tags["Aegis:Reason"],
      tags["Aegis:LastFix"],
      tags["Aegis:LastSeen"],
      tags["Aegis:Remediator"],
    ]
  }
  
}
