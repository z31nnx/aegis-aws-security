variable "region" {
  type = string
}
variable "environment" {
  type = string
}
variable "project" {
  type = string
}
variable "owner" {
  type = string
}
variable "managedby" {
  type = string
}
variable "main_username" {
  type = string
}
variable "target_role_arns" {
  type = list(string)
}
variable "trail_name" {
  type = string
}
variable "event_bus_name" {
  type = string
}
variable "sns_emails_medium" {
  type = list(string)
}
variable "sns_emails_high" {
  type = list(string)
}
