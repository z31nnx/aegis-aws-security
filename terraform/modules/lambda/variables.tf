variable "prefix" {
  type = string
}
variable "function_name" {
  type = string
}
variable "runtime" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "sns_topic_arn" {
  type = string
}
variable "role_arns" {
  type = list(string)
}
variable "memory_size" {
  type    = number
  default = 256
}
variable "timeout" {
  type    = number
  default = 30
}
variable "log_format" {
  type    = string
  default = "JSON"
}
variable "deletion_protection_enabled" {
  type    = bool
  default = false
}
variable "log_group_class" {
  type    = string
  default = "STANDARD"
}
variable "retention_in_days" {
  type    = number
  default = 7
}
variable "lambda_environment_variables" {
  description = "Environment variables"
  type        = map(string)
  default     = {}
}
variable "extra_statements" {
  type = list(object({
    sid       = string
    effect    = string
    actions   = list(string)
    resources = list(string)
  }))
  default = []
}