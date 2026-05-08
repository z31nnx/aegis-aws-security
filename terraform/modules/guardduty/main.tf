resource "aws_guardduty_detector" "detector" {
  enable                       = var.enable
  region                       = var.region
  finding_publishing_frequency = var.finding_publishing_frequency
}

resource "aws_guardduty_detector_feature" "feature" {
  for_each    = { for feature in var.features : feature.name => feature }
  detector_id = aws_guardduty_detector.detector.id
  name        = each.value.name
  status      = each.value.status

  dynamic "additional_configuration" {
    for_each = each.value.additional_configuration != null ? each.value.additional_configuration : []
    iterator = add
    content {
      name   = add.value.name
      status = add.value.status
    }
  }
}