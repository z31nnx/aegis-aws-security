variable "prefix" {
  type = string
}
variable "config_name" {
  type = string
}
variable "all_supported" {
  type = bool
}
variable "role_arn" {
  type = string
}
variable "include_global_resource_types" {
  type = bool
}
variable "recording_frequency" {
  type = string
}
variable "bucket_name" {
  type = string
}
variable "s3_prefix" {
  type = string
}
variable "rules" {
  type = list(object({
    name              = string
    owner             = string
    source_identifier = string
  }))
}