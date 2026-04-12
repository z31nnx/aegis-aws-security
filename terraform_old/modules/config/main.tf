data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config_role" {
  name               = "${var.name_prefix}-${var.config_role_name}"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Custom config role to assume, sometimes thethe managed role doesn't exist, this allow the code to run smooth during terraform apply 

resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "${var.name_prefix}-${var.config_name}-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "config_delivery_channel" {
  name           = "${var.name_prefix}-${var.config_name}-delivery-channel"
  s3_bucket_name = var.central_logs_bucket_name
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.config_recorder]
}

resource "aws_config_configuration_recorder_status" "config_status" {
  name       = aws_config_configuration_recorder.config_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.config_delivery_channel]
}

resource "aws_config_config_rule" "managed_rules" {
  for_each = { for rule in var.config_rules : rule.name => rule }

  name = each.value.name
  source {
    owner             = "AWS"
    source_identifier = each.value.source_identifier
  }
  depends_on = [
    aws_config_configuration_recorder.config_recorder,
    aws_config_delivery_channel.config_delivery_channel
  ]
}
