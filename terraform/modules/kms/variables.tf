variable "name_prefix" {
  type = string
}

variable "kms_key_alias" {
  type        = string
  description = "Alias name for the KMS key"
}

variable "main_username" {
  type        = string
  description = "Your username in the console"
}

variable "cloudtrail_name" {
  type = module
}
variable "central_logs_bucket_arn" {
  type = module
}
