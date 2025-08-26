data "aws_caller_identity" "me" {}

locals {
  global_tags = var.global_tags
  account_id  = data.aws_caller_identity.me
}
