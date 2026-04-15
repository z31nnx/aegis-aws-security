variable "prefix" {
  type = string
}
variable "dashboard_name" {
  type = string
}
variable "region" {
  type    = string
  default = null
}

variable "widgets" {
  type = list(object({
    type   = string
    x      = number
    y      = number
    width  = number
    height = number

    properties = object({
      metrics = list(list(string))
      period  = number
      stat    = string
      region  = optional(string)
      title   = string
    })
  }))
}
