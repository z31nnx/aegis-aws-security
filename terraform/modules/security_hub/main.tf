resource "aws_securityhub_account" "main" {
  region                    = var.region
  enable_default_standards  = var.enable_default_standards
  control_finding_generator = var.control_finding_generator
  auto_enable_controls      = var.auto_enable_controls
}

resource "aws_securityhub_standards_subscription" "standards" {
  for_each = toset(var.standards)

  standards_arn = each.value
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_product_subscription" "products" {
  for_each = toset(var.product_subscriptions)

  product_arn = each.value
  depends_on  = [aws_securityhub_account.main]
}