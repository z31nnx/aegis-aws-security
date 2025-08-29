variable "name_prefix" {
  type = string
}

variable "cloudtrail_name" {}
variable "cloudtrail_arn" {}

variable "lambda_cloudtrail_tamper_shield_function_arn" {}
variable "lambda_cloudtrail_tamper_shield_function_name" {}
variable "lambda_ssh_remediation_function_arn" {}
variable "lambda_ssh_remediation_function_name" {}