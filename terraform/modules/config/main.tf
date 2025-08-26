data "aws_iam_role" "config_slr" {
  name = "AWSServiceRoleForConfig"
}

resource "aws_config_configuration_recorder" "aegis_config_recorder" {
  name     = "${var.config_name}-recorder"
  role_arn = data.aws_iam_role.config_slr.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "aegis_config_delivery_channel" {
  name           = "${var.config_name}-delivery-channel"
  s3_bucket_name = var.central_logs_bucket_name
  s3_key_prefix  = "config"
}

resource "aws_config_configuration_recorder_status" "aegis_config_status" {
  name       = aws_config_configuration_recorder.aegis_config_recorder.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.aegis_config_delivery_channel]
}


resource "aws_config_config_rule" "ec2_ebs_encryption_by_default" {
  name = "${var.config_name}-ec2-ebs-encryption-by-default"
  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }
  tags = var.global_tags
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "ec2_imdsv2_check" {
  name = "${var.config_name}-ec2-imdsv2-check"
  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }
  tags = var.global_tags
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "restricted_common_ports" {
  name = "${var.config_name}-restricted-common-ports"
  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  tags = var.global_tags
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "restricted_ssh" {
  name = "${var.config_name}-restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  tags = var.global_tags
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}

resource "aws_config_config_rule" "s3_bucket_level_public_access_prohibited" {
  name = "${var.config_name}-s3-bucket-level-public-access-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }
  tags = var.global_tags
  depends_on = [
    aws_config_configuration_recorder.aegis_config_recorder,
    aws_config_delivery_channel.aegis_config_delivery_channel
  ]
}
