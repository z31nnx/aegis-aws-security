variable "name_prefix" {}
variable "sns_alerts_high_arn" {}
variable "sns_alerts_medium_arn" {}
variable "project" {}
variable "environment" {}
variable "owner" {}
variable "managedby" {}

variable "cloudtrail_name" {}
variable "central_logs_bucket" {}
variable "kms_key_arn" {}
variable "quarantine_sg_id" {}
variable "aegis_lambda_dlq_arn" {}

variable "cloudtrail_tamper_function_exec_role_name" {}
variable "cloudtrail_tamper_function_name" {}
variable "ssh_remediation_function_exec_role_name" {}
variable "ssh_remediation_function_name" {}
variable "crypto_quarantine_function_exec_role_name" {}
variable "crypto_quarantine_function_name" {}
