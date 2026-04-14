data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "Assume"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "role" {
  name               = "${var.prefix}-${var.config_role_name}"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_config_configuration_recorder" "recorder" {
  name     = "${var.prefix}-${var.config_name}"
  role_arn = aws_iam_role.role.arn


  recording_group {
    all_supported                 = var.all_supported
    include_global_resource_types = var.include_global_resource_types
  }

  recording_mode {
    recording_frequency = var.recording_frequency
  }
}

resource "aws_iam_role_policy_attachment" "policy_attachment" {
  role       = aws_iam_role.role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_delivery_channel" "delivery" {
  name           = "${var.prefix}-${var.config_name}-delivery-channel"
  s3_bucket_name = var.bucket_name
  s3_key_prefix  = var.s3_prefix
  depends_on     = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rule" {
  for_each = { for rule in var.rules : rule.name => rule }
  name     = each.value.name
  source {
    owner             = each.value.owner
    source_identifier = each.value.source_identifier
  }
  depends_on = [aws_config_configuration_recorder.recorder, aws_config_delivery_channel.delivery]
}
