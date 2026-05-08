variable "prefix" {
  type = string
}
variable "event_bus_name" {
  type = string
}
variable "description" {
  type    = string
  default = null
}
variable "kms_key_arn" {
  type = string
}