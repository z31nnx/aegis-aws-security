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

variable "trail_name" {
  type = string
}

variable "emails" {
  type = list(string)
}
