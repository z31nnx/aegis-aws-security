resource "aws_cloudtrail" "trail" {
  name                          = "${var.prefix}-${var.trail_name}"
  s3_bucket_name                = var.bucket_id
  s3_key_prefix                 = var.s3_prefix
  kms_key_id                    = var.kms_key_arn
  is_multi_region_trail         = var.is_multi_region_trail
  enable_log_file_validation    = var.enable_log_file_validation
  include_global_service_events = var.include_global_service_events

  event_selector {
    dynamic "data_resource" {
      for_each = var.event_selector.data_resource != null ? [var.event_selector.data_resource] : []
      iterator = data
      content {
        type   = data.value.type
        values = data.value.values
      }
    }
    exclude_management_event_sources = var.event_selector.exclude_management_event_sources
    include_management_events        = var.event_selector.include_management_events
    read_write_type                  = var.event_selector.read_write_type
  }

  tags = {
    Name = "${var.prefix}-${var.trail_name}"
  }
}