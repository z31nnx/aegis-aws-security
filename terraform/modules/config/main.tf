data "aws_iam_role" "config_slr" {
  count = var.ensure_config_slr ? 0 : 1
  name  = "AWSServiceRoleForConfig"

}

# Sometimes the service role is there, sometimes its not so the goal is to create 
# one and if it doesnt exist, if it exists then read from data.aws_iam_role.config_slr

resource "aws_iam_service_linked_role" "config" {
  count            = var.ensure_config_slr ? 1 : 0
  aws_service_name = "config.amazonaws.com"
  description      = "SLR for AWS Config"
}

resource "time_sleep" "after_config_slr" {
  count           = var.ensure_config_slr ? 1 : 0
  depends_on      = [aws_iam_service_linked_role.config]
  create_duration = "10s"
}

resource "aws_config_configuration_recorder" "aegis_config_recorder" {
  name = "${var.name_prefix}-${var.config_name}-recorder"
  role_arn = coalesce(
    try(aws_iam_service_linked_role.config[0].arn, null),
    try(data.aws_iam_role.config_slr[0].arn, null)
  )

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
  depends_on = [
    aws_iam_service_linked_role.config,
    time_sleep.after_config_slr
  ]
}

resource "aws_config_delivery_channel" "aegis_config_delivery_channel" {
  name           = "${var.name_prefix}-${var.config_name}-delivery-channel"
  s3_bucket_name = var.central_logs_bucket_name
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.aegis_config_recorder]
}

resource "aws_config_configuration_recorder_status" "aegis_config_status" {
  name       = aws_config_configuration_recorder.aegis_config_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.aegis_config_delivery_channel]
}


resource "aws_config_config_rule" "ec2_ebs_encryption_by_default" {
  name = "ec2-ebs-encryption-by-default"
  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "ec2_imdsv2_check" {
  name = "ec2-imdsv2-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "restricted_common_ports" {
  name = "restricted-common-ports"
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "restricted_ssh" {
  name = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "s3_bucket_level_public_access_prohibited" {
  name = "s3-bucket-level-public-access-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "cloudtrail-enabled"
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  maximum_execution_frequency = "One_Hour"
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}
