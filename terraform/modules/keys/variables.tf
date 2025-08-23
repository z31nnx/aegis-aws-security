variable "global_tags" {
  type = map(string)
}

variable "kms_key_alias" {
  type        = string
  description = "Alias name for the KMS key"
  default     = "aegis-central-logs"
}

variable "main_username" {
  description = "Your username in the console"
}
