# Tags
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

# Defaults
variable "region" {
    type = string
}
variable "partition" {
    type = string
}

# Security Groups
variable "quarantine_sg_name" {
    type = string
}

# SSM
variable "ssm_role_name" {
    type = string
}
variable "ssm_instance_profile_name" {
    type = string
}

# SNS
variable "sns_emails" {
    type = list(string)
}
variable "sns_alerts_high_topic_name" {
    type = string
}
variable "sns_alerts_medium_topic_name" {
    type = string
}

# SQS
variable "dlq_name" {
    type = string
}

# KMS Keys
variable "main_username" {
    type = string
}
variable "kms_key_alias" {
    type = string
}

# S3 Central Logging
variable "central_bucket_name" {
    type = string
}

# Cloudtrail
variable "cloudtrail_name" {
    type = string
}

# Config
variable "config_name" {
    type = string
}
variable "config_role_name" {
    type = string
}

# Eventbridge

# Lambda
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
