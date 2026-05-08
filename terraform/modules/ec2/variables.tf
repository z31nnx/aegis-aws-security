variable "prefix" {
  type = string
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

variable "metadata_http_tokens" {
  type    = string
  default = "required"
}

variable "root_block_device_encrypted" {
  type    = bool
  default = true
}
