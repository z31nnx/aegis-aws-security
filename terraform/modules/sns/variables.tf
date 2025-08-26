variable "global_tags" {
  type = map(string)
}

variable "sns_alerts_high_topic_name" {
  default = "Aegis-Security-High"
}
variable "sns_alerts_medium_topic_name" {
  default = "Aegis-Security-Medium"
}