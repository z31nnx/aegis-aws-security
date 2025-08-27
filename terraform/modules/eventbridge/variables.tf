variable "global_tags" {
  type = map(string)
}

variable "cloudtrail_name" {}
variable "cloudtrail_arn" {}
variable "lambda_cloudtrail_tamper_shield_arn" {}