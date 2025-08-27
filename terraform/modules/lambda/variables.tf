variable "global_tags" {
  type = map(string)
}

variable "sns_alerts_high_arn" {
  type        = string
  description = "SNS topic ARN for High severity alerts"
}

variable "sns_alerts_medium_arn" {
  type        = string
  description = "SNS topic ARN for Medium severity alerts"
}


variable "cloudtrail_name" {}
variable "central_logs_bucket" {}
variable "kms_key_arn" {}

variable "lambda_cloudtrail_tamper_exec_role_name" {}
variable "lambda_cloudtrail_tamper_function_name" {}
