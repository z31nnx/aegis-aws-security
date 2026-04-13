data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

module "main_key" {
  source                  = "../../../modules/kms"
  key_alias               = "central-key"
  description             = "Main key for ${local.prefix}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
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
        type        = "AWS"
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
        type        = "AWS"
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
        type        = "AWS"
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
    }
  ]

  prefix = local.prefix
}