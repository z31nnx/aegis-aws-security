resource "aws_cloudwatch_dashboard" "dashboard" {
  dashboard_name = "${var.prefix}-${var.dashboard_name}"
  dashboard_body = var.dashboard_body
}
