variable "prefix" {
  type = string
}
variable "rule_name" {
  type = string
}
variable "description" {
  type    = string
  default = null
}
variable "event_bus_name" {
  type = string
}
variable "state" {
  type = string
}
variable "target_arn" {
  type = string
}
variable "target_id" {
  type = string
}
variable "event_pattern" {
  type = string
}