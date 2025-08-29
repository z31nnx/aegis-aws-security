variable "name_prefix" {
  type = string
}

variable "ensure_config_slr" {
  type        = bool
  default     = true
  description = "Create AWSServiceRoleForConfig when missing"
}

variable "config_name" {}
variable "central_logs_bucket_name" {}