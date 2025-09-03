locals {
  account_id = data.aws_caller_identity.me.account_id
  region     = var.region
}
