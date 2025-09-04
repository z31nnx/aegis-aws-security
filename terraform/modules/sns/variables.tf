variable "name_prefix" {}

variable "sns_emails" {
  type        = list(string)
  sensitive   = false # set to true if not using for_each, otherwise it breaks 
  default     = []
  description = "Default sns emails for subscriptions"
}

variable "sns_alerts_high_topic_name" {}
variable "sns_alerts_medium_topic_name" {}
variable "kms_key_arn" {}