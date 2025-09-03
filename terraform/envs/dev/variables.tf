# Tags
variable "project" {}
variable "environment" {}
variable "owner" {}
variable "managedby" {}

# Defaults
variable "region" {}
variable "partition" {}

# Security Groups
variable "quarantine_sg_name" {}

# SSM
variable "ssm_role_name" {}
variable "ssm_instance_profile_name" {}

# SNS
variable "sns_emails" {}

# KMS Keys
variable "main_username" {}
variable "kms_key_alias" {}

# S3 Central Logging
variable "central_bucket_name" {}

# Cloudtrail
variable "cloudtrail_name" {}

# Config
variable "config_name" {}
variable "config_role_name" {}

# Eventbridge

# Lambda
variable "lambda_cloudtrail_tamper_function_exec_role_name" {}
variable "lambda_cloudtrail_tamper_function_name" {}
variable "lambda_ssh_remediation_function_exec_role_name" {}
variable "lambda_ssh_remediation_function_name" {}
variable "lambda_crypto_quarantine_function_exec_role_name" {}
variable "lambda_crypto_quarantine_function_name" {}
