variable "prefix" {
  type = string
}
variable "sg_name" {
  type = string
}
variable "description" {
  type    = string
  default = null
}
variable "vpc_id" {
  type    = string
  default = null
}

variable "extra_tags" {
  type = map(string)
  default = {}
}

variable "ingress" {
  type = map(object({
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    from_port                    = optional(number)
    to_port                      = optional(number)
    ip_protocol                  = string
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
  }))
  default = {}
}

variable "egress" {
  type = map(object({
    cidr_ipv4                    = optional(string)
    cidr_ipv6                    = optional(string)
    from_port                    = optional(number)
    to_port                      = optional(number)
    ip_protocol                  = string
    prefix_list_id               = optional(string)
    referenced_security_group_id = optional(string)
  }))
  default = {}
}
