resource "aws_cloudwatch_dashboard" "dashboard" {
  dashboard_name = "${var.prefix}-${var.dashboard_name}"

  dashboard_body = jsonencode({
    widgets = [
      for widget in var.widgets : {
        type   = widget.type
        x      = widget.x
        y      = widget.y
        width  = widget.width
        height = widget.height

        properties = {
          metrics = widget.properties.metrics
          period  = widget.properties.period
          stat    = widget.properties.stat
          region  = coalesce(widget.properties.region, var.region)
          title   = widget.properties.title
        }
      }
    ]
  })
}
