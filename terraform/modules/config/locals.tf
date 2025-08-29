data "aws_caller_identity" "me" {}

locals {
  account_id = data.aws_caller_identity.me
}
