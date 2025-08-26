resource "aws_kms_key" "central_logs_key" {
  description             = "Main key for central logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.central_logs_policy.json

  tags = local.global_tags
}

resource "aws_kms_alias" "central_logs_key_alias" {
  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.central_logs_key.key_id
}

data "aws_iam_policy_document" "central_logs_policy" {
  # Root
  statement {
    sid     = "RootAdmin"
    effect  = "Allow"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root", ]
    }
    resources = ["*"]
  }

  # Named key admins 
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
      identifiers = ["arn:aws:iam::${local.account_id}:user/${var.main_username}", "arn:aws:iam::${local.account_id}:role/admin"]
    }
    resources = ["*"]
  }

statement {
    sid     = "AllowS3ViaServiceForThisBucket"
    effect  = "Allow"
    principals { 
      type = "Service" 
      identifiers = ["s3.amazonaws.com"] 
      }
    actions  = ["kms:GenerateDataKey*","kms:Encrypt","kms:Decrypt","kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:s3:arn"
      values   = ["${var.central_logs_bucket_arn}/*"]
    }
  }  

  # Allow CloudTrail to use the key (GenerateDataKey/Encrypt/Decrypt/Describe)

statement {
  sid     = "AllowCloudTrailGenerateDataKey"
  effect  = "Allow"
  principals { 
    type = "Service"
    identifiers = ["cloudtrail.amazonaws.com"] 
    }
  actions  = ["kms:GenerateDataKey*"]
  resources = ["*"]
  condition {
    test     = "StringEquals"
    variable = "aws:SourceArn"
    values   = ["arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.cloudtrail_name}"]
  }
  condition {
    test     = "StringLike"
    variable = "kms:EncryptionContext:aws:cloudtrail:arn"
    values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
  }
}

statement {
  sid     = "AllowCloudTrailDescribeKey"
  effect  = "Allow"
  principals { 
    type = "Service" 
    identifiers = ["cloudtrail.amazonaws.com"]
     }
  actions  = ["kms:DescribeKey"]
  resources = ["*"]
}

  # Allow AWS Config 
  statement {
    sid     = "AllowConfigUseViaService"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    principals {
      type        = "Service"
      identifiers = [local.sp_config]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.sp_config]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

statement {
  sid     = "AllowCloudTrailCreateGrantForAWSResource"
  effect  = "Allow"
  principals { 
    type = "Service" 
    identifiers = ["cloudtrail.amazonaws.com"] 
    }
  actions  = ["kms:CreateGrant"]
  resources = ["*"]
  condition {
    test     = "Bool"
    variable = "kms:GrantIsForAWSResource"
    values   = ["true"]
  }
  condition {
    test     = "StringEquals"
    variable = "aws:SourceArn"
    values   = ["arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.cloudtrail_name}"]
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

  # Allow CloudWatch Logs (for KMS-encrypted log groups / exports)
  statement {
    sid     = "AllowCloudWatchLogsUseViaService"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    principals {
      type        = "Service"
      identifiers = [local.sp_logs]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = [local.sp_logs]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}


