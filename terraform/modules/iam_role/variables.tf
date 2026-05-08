variable "prefix" {
  type = string
}
variable "role_name" {
  type = string
}
variable "path" {
  type    = string
  default = "/"
}
variable "description" {
  type    = string
  default = null
}
variable "max_session_duration" {
  type    = number
  default = 3600
}
variable "policy_arns" {
  type    = list(string)
  default = []
}

variable "trust_policy" {
  type = list(object({
    sid     = optional(string)
    effect  = string
    actions = list(string)

    principals = object({
      type        = string
      identifiers = list(string)
    })

    conditions = optional(list(object({
      test     = string
      variable = string
      values   = list(string)
    })))
  }))
}

variable "policy" {
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