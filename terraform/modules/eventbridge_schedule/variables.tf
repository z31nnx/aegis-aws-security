variable "prefix" {
  type = string
}
variable "schedule_group_name" {
  type = string
}
variable "role_policy" {
  type = list(object({
    sid       = string
    effect    = string
    actions   = list(string)
    resources = list(string)
  }))
  default = []
}

variable "rules" {
  type = map(object({
    state                = string
    flexible_time_window = string
    schedule_expression  = string
    target_arn           = string
  }))
  default = {}
}