variable "global_tags" {
  type = map(string)
}

variable "lambda_cloudtrail_tamper_exec_role_name" {}

variable "sns_alerts_high_arn" {
  type        = string
  description = "SNS topic ARN for High severity alerts"
}

variable "sns_alerts_medium_arn" {
  type        = string
  description = "SNS topic ARN for Medium severity alerts"
}
