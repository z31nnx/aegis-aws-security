variable "prefix" {
  type = string
}
variable "topic_name" {
  type = string
}
variable "protocol" {
  type = string
}
variable "kms_key_arn" {
  type = string
}
variable "description" {
  type    = string
  default = null
}
variable "emails" {
  type    = list(string)
  default = []
}