variable "prefix" {
  type = string
}
variable "function_name" {
  type = string
}
variable "description" {
  type    = string
  default = null
}
variable "role_arn" {
  type = string
}
variable "runtime" {
  type = string
}
variable "filename" {
  type = string
}
variable "source_code_hash" {
  type = string
}
variable "timeout" {
  type = number
}
variable "memory_size" {
  type = number
}
variable "publish" {
  type = bool
}