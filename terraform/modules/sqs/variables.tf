variable "name_prefix" {
  type = string
}

variable "dlq_name" {}
variable "kms_key_arn" {}
variable "cloudtrail_tamper_function_arn" {}
variable "ssh_remediation_function_arn" {}
variable "crypto_quarantine_function_arn" {}