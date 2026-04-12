data "aws_region" "current" {}
data "aws_partition" "current" {}

resource "aws_securityhub_account" "main" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
}

resource "aws_securityhub_standards_subscription" "standards" {
  for_each      = local.standards
  standards_arn = each.value

  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_product_subscription" "products" {
  for_each    = local.product_subscriptions
  product_arn = each.value

  depends_on = [aws_securityhub_account.main]
}