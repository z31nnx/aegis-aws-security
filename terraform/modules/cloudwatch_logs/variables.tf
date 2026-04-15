variable "prefix" {
  type = string
}
variable "log_group_name" {
  type = string
}
variable "deletion_protection_enabled" {
  type = bool
}
variable "log_group_class" {
  type = string
  default = "STANDARD"
}
variable "retention_in_days" {
  type = number
  default = 7
}
variable "kms_key_arn" {
  type = string
}