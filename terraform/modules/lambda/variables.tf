variable "name_prefix" {
  type = string
}
variable "sns_alerts_high_arn" {
  type = module
}
variable "sns_alerts_medium_arn" {
  type = module
}
variable "project" {
  type = string
}
variable "environment" {
  type = string
}
variable "owner" {
  type = string
}
variable "managedby" {
  type = string
}

variable "cloudtrail_name" {
  type = module
}
variable "central_logs_bucket" {
  type = module
}
variable "kms_key_arn" {
  type = module
}
variable "quarantine_sg_id" {
  type = module
}
variable "aegis_lambda_dlq_arn" {
  type = module
}

variable "cloudtrail_tamper_function_exec_role_name" {
  type = string
}
variable "cloudtrail_tamper_function_name" {
  type = string
}
variable "ssh_remediation_function_exec_role_name" {
  type = string
}
variable "ssh_remediation_function_name" {
  type = string
}
variable "crypto_quarantine_function_exec_role_name" {
  type = string
}
variable "crypto_quarantine_function_name" {
  type = string
}
