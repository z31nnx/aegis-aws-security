variable "region" {
  type    = string
  default = null
}
variable "enable_default_standards" {
  type = bool
}
variable "control_finding_generator" {
  type = string
}
variable "auto_enable_controls" {
  type = bool
}
variable "standards" {
  type = list(string)
}
variable "product_subscriptions" {
  type = list(string)
}