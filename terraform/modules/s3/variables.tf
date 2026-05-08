variable "prefix" {
  type = string
}
variable "bucket_name" {
  type = string
}
variable "force_destroy" {
  type    = bool
  default = false
}
variable "versioning" {
  type    = string
  default = "Enabled"
}
variable "public_access_block" {
  type = object({
    block_public_acls       = bool
    block_public_policy     = bool
    ignore_public_acls      = bool
    restrict_public_buckets = bool
  })
}

variable "server_side_encryption" {
  type = object({
    kms_key_arn        = string
    sse_algorithm      = string
    bucket_key_enabled = bool
  })
}

variable "bucket_policy" {
  type = list(object({
    sid       = string
    effect    = string
    actions   = list(string)
    resources = optional(list(string))

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
  default = []
}