data "aws_iam_role" "config_service_role" {
  name = "AWSServiceRoleForConfig"
}

# Sometimes the service role is there, sometimes its not. If theres error, create the AWSServiceRoleForConfig in the IAM role console

resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "${var.name_prefix}-${var.config_name}-recorder"
  role_arn = data.aws_iam_role.config_service_role.arn

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
