data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

module "main_key" {
  source                  = "../../../modules/kms"
  key_alias               = "central-key"
  description             = "Main key for ${local.prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  prevent_destroy         = false

  key_policy = [
    {
      sid     = "RootAdmin"
      effect  = "Allow"
      actions = ["kms:*"]
      principals = {
        type        = "AWS"
        identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
      }
      resources  = ["*"]
      conditions = []
    },
    {
      sid    = "AllowAccessForKeyAdministrators"
      effect = "Allow"
      actions = [
        "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*",
        "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
        "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand"
      ]
      principals = {
        type = "AWS"
        identifiers = [
          "arn:${local.partition}:iam::${local.account_id}:user/${var.main_username}",
          "arn:${local.partition}:iam::${local.account_id}:role/admin"
        ]
      }
      resources  = ["*"]
      conditions = []
    },
    {
      sid     = "AllowUseOfTheKey"
      effect  = "Allow"
      actions = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      principals = {
        type = "AWS"
        identifiers = [
          "arn:${local.partition}:iam::${local.account_id}:user/${var.main_username}",
          "arn:${local.partition}:iam::${local.account_id}:role/admin"
        ]
      }
      resources  = ["*"]
      conditions = []
    },
    {
      sid     = "AllowAttachmentOfPersistentResources"
      effect  = "Allow"
      actions = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
      principals = {
        type = "AWS"
        identifiers = [
          "arn:${local.partition}:iam::${local.account_id}:user/${var.main_username}",
          "arn:${local.partition}:iam::${local.account_id}:role/admin"
        ]
      }
      resources = ["*"]
      conditions = [
        {
          test     = "Bool"
          variable = "kms:GrantIsForAWSResource"
          values   = ["true"]
        }
      ]
    },
    {
      sid     = "AllowCloudTrailGenerateDataKey"
      effect  = "Allow"
      actions = ["kms:GenerateDataKey*", "kms:DescribeKey", "kms:Decrypt", "kms:Encrypt"]
      principals = {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      conditions = [
        {
          test     = "StringEquals"
          variable = "aws:SourceArn"
          values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.prefix}-${var.trail_name}"]
        },
        {
          test     = "StringLike"
          variable = "kms:EncryptionContext:aws:cloudtrail:arn"
          values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
        }
      ]
      resources = ["*"]
    },
    {
      sid     = "AllowCloudTrailDescribeKey"
      effect  = "Allow"
      actions = ["kms:DescribeKey"]
      principals = {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      conditions = []
      resources  = ["*"]
    },
    {
      sid     = "AllowCloudTrailCreateGrantForAWSResource"
      effect  = "Allow"
      actions = ["kms:CreateGrant"]
      principals = {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      resources = ["*"]
      conditions = [
        {
          test     = "Bool"
          variable = "kms:GrantIsForAWSResource"
          values   = ["true"]
        },
        {
          test     = "StringEquals"
          variable = "aws:SourceArn"
          values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.prefix}-${var.trail_name}"]
        }
      ]
    }
  ]

  prefix = local.prefix
}

module "central-logs-bucket" {
  source        = "../../../modules/s3"
  bucket_name   = "central-security-logs"
  force_destroy = true
  versioning    = "Enabled"
  public_access_block = {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
  server_side_encryption = {
    kms_key_arn        = module.main_key.key_arn
    sse_algorithm      = "aws:kms"
    bucket_key_enabled = true
  }
  bucket_policy = [
    {
      sid     = "AllowCloudTrailGetBucketAcl"
      effect  = "Allow"
      actions = ["s3:GetBucketAcl"]
      principals = {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      resources = [local.bucket_arn]
      conditions = [
        {
          test     = "StringEquals"
          variable = "aws:SourceArn"
          values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.prefix}-${var.trail_name}"]
        }
      ]
    },
    {
      sid     = "AllowCloudTrailListBucket"
      effect  = "Allow"
      actions = ["s3:ListBucket"]
      principals = {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      resources = [local.bucket_arn]
      conditions = [
        {
          test     = "StringEquals"
          variable = "aws:SourceArn"
          values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/*"]
        }
      ]
    },
    {
      sid     = "AllowCloudTrailPutObject"
      effect  = "Allow"
      actions = ["s3:PutObject"]
      principals = {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      resources = ["${local.bucket_arn}/cloudtrail/AWSLogs/${local.account_id}/*"]
      conditions = [
        {
          test     = "StringEquals"
          variable = "s3:x-amz-acl"
          values   = ["bucket-owner-full-control"]
        },
        {
          test     = "StringEquals"
          variable = "aws:SourceArn"
          values   = ["arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.prefix}-${var.trail_name}"]
        }
      ]
    },
    {
      sid     = "AWSConfigBucketPermissionsCheck"
      effect  = "Allow"
      actions = ["s3:GetBucketAcl"]
      principals = {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]

      }
      resources = [local.bucket_arn]
      conditions = [
        {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = [local.account_id]
        }
      ]
    },
    {
      sid     = "AWSConfigBucketExistenceCheck"
      effect  = "Allow"
      actions = ["s3:ListBucket"]
      principals = {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      resources = [local.bucket_arn]
      conditions = [
        {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = [local.account_id]
        }
      ]
    },
    {
      sid     = "AWSConfigBucketDelivery"
      effect  = "Allow"
      actions = ["s3:PutObject"]
      principals = {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
      resources = ["${local.bucket_arn}/config/AWSLogs/${local.account_id}/*"]
      conditions = [
        {
          test     = "StringEquals"
          variable = "s3:x-amz-acl"
          values   = ["bucket-owner-full-control"]
        },
        {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = [local.account_id]
        }
      ]
    }
  ]
  prefix = local.prefix
}

module "main_trail" {
  source                        = "../../../modules/cloudtrail"
  trail_name                    = var.trail_name
  bucket_id                     = module.central-logs-bucket.bucket_id
  s3_prefix                     = "cloudtrail"
  kms_key_arn                   = module.main_key.key_arn
  include_global_service_events = false
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector = {
    include_management_events = true
    read_write_type           = "All"
  }
  prefix     = local.prefix
  depends_on = [module.central-logs-bucket]
}

module "ebs_encryption" {
  source = "../../../modules/ebs"
  enable = true
}

module "config" {
  source                        = "../../../modules/config"
  config_role_name              = "config-role"
  config_name                   = "config"
  all_supported                 = true
  include_global_resource_types = true
  recording_frequency           = "CONTINUOUS"
  bucket_name                   = module.central-logs-bucket.bucket
  s3_prefix                     = "config"
  rules = [
    {
      owner             = "AWS"
      name              = "ec2-ebs-encryption-by-default"
      source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
    },
    {
      owner             = "AWS"
      name              = "ec2-imdsv2-check"
      source_identifier = "EC2_IMDSV2_CHECK"
    },
    {
      owner             = "AWS"
      name              = "restricted-common-ports"
      source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
    },
    {
      owner             = "AWS"
      name              = "restricted-ssh"
      source_identifier = "INCOMING_SSH_DISABLED"
    },
    {
      owner             = "AWS"
      name              = "s3-bucket-level-public-access-prohibited"
      source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    },
    {
      owner             = "AWS"
      name              = "cloudtrail-enabled"
      source_identifier = "CLOUD_TRAIL_ENABLED"
    },
    {
      owner             = "AWS"
      name              = "iam-user-mfa-enabled"
      source_identifier = "IAM_USER_MFA_ENABLED"
    }
  ]
  prefix = local.prefix
}