variable "name_prefix" {
  type = string
}

variable "public_subnets" {
  type = map(object({
    cidr_block = string
    az         = string
  }))
  default = {}
}

variable "private_subnets" {
  type = map(object({
    cidr_block = string
    az         = string
  }))
  default = {}
}

variable "vpc_name" {}
variable "cidr_block" {}
