data "aws_caller_identity" "me" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

resource "aws_kms_key" "aegis_key" {
  description             = "Main key for aegis"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.aegis_key_policy.json

  lifecycle {
    prevent_destroy = false # set true to prevent accidental deletion
  }

}

resource "aws_kms_alias" "aegis_key_alias" {
  name          = "alias/${var.name_prefix}-${var.kms_key_alias}"
  target_key_id = aws_kms_key.aegis_key.key_id
}

data "aws_iam_policy_document" "aegis_key_policy" {
  # Root
  statement {
    sid     = "RootAdmin"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root", ]
    }
    resources = ["*"]
  }

  # Key admins 
  statement {
    sid    = "KeyAdminsNoDecrypt"
    effect = "Allow"
    actions = [
      "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
      "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion", "kms:TagResource", "kms:UntagResource"
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:user/${var.main_username}", "arn:aws:iam::${local.account_id}:role/admin"]
    }
    resources = ["*"]
  }

  # Key users
  statement {
    sid     = "Allow use of the key"
    effect  = "Allow"
    actions = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:user/${var.main_username}", "arn:aws:iam::${local.account_id}:role/admin"]
    }
    resources = ["*"]
  }


  # Allow SNS to use this key for topics
  statement {
    sid    = "AllowSNSUseOfKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:sns:topicArn"
      values   = ["arn:${local.partition}:sns:${local.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid    = "AllowS3ViaServiceForThisBucket"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${var.central_logs_bucket_arn}/*"]
    }
  }

  # Allow CloudTrail to use the key

  statement {
    sid    = "AllowCloudTrailGenerateDataKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:Encrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${var.name_prefix}-${var.cloudtrail_name}"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailDescribeKey"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailCreateGrantForAWSResource"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:CreateGrant"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${var.name_prefix}-${var.cloudtrail_name}"]
    }
  }

  # Allow AWS Config 
  statement {
    sid     = "AllowConfigUseViaService"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "AllowS3ForConfigWrites"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${var.central_logs_bucket_arn}/*"]
    }
  }

  # Allow SQS to use this key for queues
  statement {
    sid     = "AllowSQSUseOfCMK"
    effect  = "Allow"
    actions = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]

    principals {
      type        = "Service"
      identifiers = ["sqs.amazonaws.com"]
    }

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["sqs.${local.region}.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }

  # Allow CloudWatch Logs
  statement {
    sid     = "AllowCloudWatchLogsUseViaService"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}


