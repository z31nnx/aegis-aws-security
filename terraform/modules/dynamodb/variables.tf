variable "prefix" {
  type = string
}
variable "table_name" {
  type = string
}
variable "deletion_protection" {
  type = bool
}
variable "billing_mode" {
  type = string
}
variable "read_capacity" {
  type    = number
  default = null
}
variable "write_capacity" {
  type    = number
  default = null
}
variable "hash_key" {
  type    = string
  default = null
}
variable "range_key" {
  type    = string
  default = null
}
variable "server_side_encryption" {
  type = object({
    enabled     = bool
    kms_key_arn = string
  })
}
variable "ttl" {
  type = object({
    attribute_name = string
    enabled        = bool
  })
}
variable "attribute" {
  type = map(object({
    name = optional(string)
    type = optional(string)
  }))
  default = {}
}