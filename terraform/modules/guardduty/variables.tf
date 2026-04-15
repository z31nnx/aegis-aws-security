variable "enable" {
  type = bool
}
variable "region" {
  type = string
}
variable "features" {
  type = list(object({
    name   = string
    status = string

    additional_configuration = optional(list(object({
      name   = string
      status = string
    })))
  }))
}