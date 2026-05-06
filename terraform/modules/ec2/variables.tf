variable "prefix" {
  type = string
}

variable "ami" {
  type    = string
  default = null
}
variable "instance_name" {
  type = string
}
variable "associate_public_ip_address" {
  type = bool
}
variable "force_destroy" {
  type = bool
}
variable "iam_instance_profile" {
  type    = string
  default = null
}
variable "instance_type" {
  type = string
}
variable "key_name" {
  type    = string
  default = null
}
variable "vpc_security_group_ids" {
  type = list(string)
}
variable "subnet_id" {
  type    = string
  default = null
}
