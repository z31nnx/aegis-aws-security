variable "name_prefix" {
  type = string
}

variable "dlq_name" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "cloudtrail_tamper_function_arn" {
  type = string
}
variable "ssh_remediation_function_arn" {
  type = string
}
variable "crypto_quarantine_function_arn" {
  type = string
}