data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  global_tags   = var.global_tags
  account_id    = data.aws_caller_identity.me.account_id
  sp_cloudtrail = "cloudtrail.amazonaws.com"
  sp_config     = "config.amazonaws.com"
  sp_logs       = "logs.${local.region}.amazonaws.com"
  region = data.aws_region.current.id
}
