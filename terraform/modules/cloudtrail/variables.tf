variable "prefix" {
  type = string
}
variable "trail_name" {
  type = string
}
variable "bucket_id" {
  type = string
}
variable "s3_prefix" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "include_global_service_events" {
  type = bool
}
variable "is_multi_region_trail" {
  type = bool
}
variable "enable_log_file_validation" {
  type = bool
}

variable "event_selector" {
  type = object({
    data_resource = optional(object({
      type   = string
      values = list(string)
    }))
    exclude_management_event_sources = optional(list(string))
    include_management_events        = bool
    read_write_type                  = string
  })
}