variable "name_prefix" {
  type = string
}

variable "cloudtrail_name" {}
variable "cloudtrail_arn" {}

variable "cloudtrail_tamper_function_arn" {}
variable "cloudtrail_tamper_function_name" {}
variable "ssh_remediation_function_arn" {}
variable "ssh_remediation_function_name" {}
variable "crypto_quarantine_function_arn" {}
variable "crypto_quarantine_function_name" {}

