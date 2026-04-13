variable "prefix" {
  type = string
}
variable "description" {
  type    = string
  default = null
}
variable "enable_key_rotation" {
  type    = bool
  default = true
}
variable "deletion_window_in_days" {
  type    = number
  default = 30
}
variable "prevent_destroy" {
  type    = bool
  default = true
}
variable "key_alias" {
  type = string
}

variable "key_policy" {
  type = list(object({
    sid       = string
    effect    = string
    actions   = list(string)
    resources = optional(list(string))

    principals = object({
      type        = string
      identifiers = list(string)
    })

    conditions = list(object({
      test     = string
      variable = string
      values   = list(string)
    }))
  }))
  default = []
}