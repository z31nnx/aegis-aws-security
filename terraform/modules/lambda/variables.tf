variable "name_prefix" {
  type = string
}

variable "sns_alerts_high_arn" {
  type        = string
  description = "SNS topic ARN for High severity alerts"
}

variable "sns_alerts_medium_arn" {
  type        = string
  description = "SNS topic ARN for Medium severity alerts"
}

variable "sns_alerts_kms_key_arn" {
  type        = string
  description = "KMS key ARN used by SNS topics (if encrypted)"
  default     = ""
}

variable "project" {}
variable "environment" {}
variable "owner" {}
variable "managedby" {}

variable "cloudtrail_name" {}
variable "central_logs_bucket" {}
variable "kms_key_arn" {}
variable "quarantine_sg_id" {}

variable "lambda_cloudtrail_tamper_function_exec_role_name" {}
variable "lambda_cloudtrail_tamper_function_name" {}
variable "lambda_ssh_remediation_function_exec_role_name" {}
variable "lambda_ssh_remediation_function_name" {}
variable "lambda_crypto_quarantine_function_exec_role_name" {}
variable "lambda_crypto_quarantine_function_name" {}
