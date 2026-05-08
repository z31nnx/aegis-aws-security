variable "enable" {
  type = bool
}
variable "region" {
  type    = string
  default = null
}
variable "finding_publishing_frequency" {
  type    = string
  default = "SIX_HOURS"
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