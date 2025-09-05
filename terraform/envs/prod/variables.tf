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
variable "sns_alerts_high_topic_name" {}
variable "sns_alerts_medium_topic_name" {}

# SQS
variable "dlq_name" {}

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
variable "cloudtrail_tamper_function_exec_role_name" {}
variable "cloudtrail_tamper_function_name" {}
variable "ssh_remediation_function_exec_role_name" {}
variable "ssh_remediation_function_name" {}
variable "crypto_quarantine_function_exec_role_name" {}
variable "crypto_quarantine_function_name" {}
