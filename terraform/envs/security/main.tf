data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

module "ebs_encryption" {
  source = "../../modules/ebs"
  enable = true
}

module "main_key" {
  source                  = "../../modules/kms"
  key_alias               = "central-key"
  description             = "Main key for ${local.prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  prevent_destroy         = false
  prefix                  = local.prefix

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
    },
    {
      sid     = "AllowSNSUseOfKey"
      effect  = "Allow"
      actions = ["kms:GenerateDataKey*", "kms:Decrypt"]
      principals = {
        type        = "Service"
        identifiers = ["sns.amazonaws.com"]
      }
      resources = ["*"]
      conditions = [
        {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = [local.account_id]
        },
        {
          test     = "StringLike"
          variable = "kms:EncryptionContext:aws:sns:topicArn"
          values   = ["arn:${local.partition}:sns:${local.region}:${local.account_id}:*"]
        }
      ]
    },
    {
      sid     = "AllowCloudWatchLogs"
      effect  = "Allow"
      actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      principals = {
        type        = "Service"
        identifiers = ["logs.${local.region}.amazonaws.com"]
      }
      resources = ["*"]
      conditions = [
        {
          test     = "StringLike"
          variable = "kms:EncryptionContext:aws:logs:arn"
          values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
        },
        {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = [local.account_id]
        }
      ]
    },
    {
      sid     = "AllowEventBridgeBus"
      effect  = "Allow"
      actions = ["kms:GenerateDataKey*", "kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      principals = {
        type        = "Service"
        identifiers = ["events.amazonaws.com"]
      }
      resources = ["*"]
      conditions = [
        {
          test     = "StringEquals"
          variable = "kms:EncryptionContext:aws:events:event-bus:arn"
          values   = ["arn:${local.partition}:events:${local.region}:${local.account_id}:event-bus/${local.prefix}-${var.event_bus_name}"]
        },
        {
          test     = "StringEquals"
          variable = "aws:SourceArn"
          values   = ["arn:${local.partition}:events:${local.region}:${local.account_id}:event-bus/${local.prefix}-${var.event_bus_name}"]
        },
        {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = [local.account_id]
        }
      ]
    }
  ]
}

module "central-logs-bucket" {
  source        = "../../modules/s3"
  bucket_name   = "central-security-logs"
  force_destroy = true
  versioning    = "Enabled"
  prefix        = local.prefix
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
}

module "main_trail" {
  source                        = "../../modules/cloudtrail"
  trail_name                    = var.trail_name
  bucket_id                     = module.central-logs-bucket.bucket_id
  s3_prefix                     = "cloudtrail"
  kms_key_arn                   = module.main_key.key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector = {
    include_management_events = true
    read_write_type           = "All"
  }
  prefix     = local.prefix
  depends_on = [module.central-logs-bucket]
}

module "guardduty" {
  source                       = "../../modules/guardduty"
  region                       = null
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  enable                       = true
  features = [
    {
      name   = "S3_DATA_EVENTS"
      status = "ENABLED"
    },
    {
      name   = "EKS_AUDIT_LOGS"
      status = "ENABLED"
    },
    {
      name   = "EBS_MALWARE_PROTECTION"
      status = "ENABLED"
    },
    {
      name   = "RDS_LOGIN_EVENTS"
      status = "ENABLED"
    },
    {
      name   = "LAMBDA_NETWORK_LOGS"
      status = "ENABLED"
    },
    {
      name   = "RUNTIME_MONITORING"
      status = "ENABLED"
      additional_configuration = [
        {
          name   = "EKS_ADDON_MANAGEMENT"
          status = "ENABLED"
        },
        {
          name   = "ECS_FARGATE_AGENT_MANAGEMENT"
          status = "ENABLED"
        },
        {
          name   = "EC2_AGENT_MANAGEMENT"
          status = "ENABLED"
        }
      ]
    }
  ]
}

module "sns_high" {
  source      = "../../modules/sns"
  topic_name  = "high-alerts"
  kms_key_arn = module.main_key.key_arn
  emails      = var.sns_emails_high
  protocol    = "email"
  prefix      = local.prefix
}

module "sns_medium" {
  source      = "../../modules/sns"
  topic_name  = "medium-alerts"
  kms_key_arn = module.main_key.key_arn
  emails      = var.sns_emails_medium
  protocol    = "email"
  prefix      = local.prefix
}

module "sns_critical" {
  source      = "../../modules/sns"
  topic_name  = "critical-alerts"
  kms_key_arn = module.main_key.key_arn
  emails      = var.sns_emails_critical
  protocol    = "email"
  prefix      = local.prefix
}

module "securityhub" {
  source                    = "../../modules/security_hub"
  region                    = null
  enable_default_standards  = true
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
  standards = [
    "arn:${local.partition}:securityhub:${local.region}::standards/aws-resource-tagging-standard/v/1.0.0"
  ]
  product_subscriptions = [
    "arn:${local.partition}:securityhub:${local.region}::product/aws/guardduty",
    "arn:${local.partition}:securityhub:${local.region}::product/aws/inspector"
  ]
  depends_on = [module.config]
}

module "config" {
  source                        = "../../modules/config"
  config_name                   = "config"
  role_arn                      = module.config_role.role_arn
  all_supported                 = true
  include_global_resource_types = true
  recording_frequency           = "CONTINUOUS"
  bucket_name                   = module.central-logs-bucket.bucket
  s3_prefix                     = "config"
  prefix                        = local.prefix
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
}

module "config_role" {
  source               = "../../modules/iam_role"
  role_name            = "config-role"
  description          = "Main IAM role for Config"
  path                 = null
  max_session_duration = null
  prefix               = local.prefix
  policy               = []
  policy_arns          = ["arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"]
  trust_policy = [
    {
      sid     = "Trust"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        type        = "Service"
        identifiers = ["config.amazonaws.com"]
      }
    }
  ]
}

module "ssm_role" {
  source               = "../../modules/iam_role"
  role_name            = "ssm-role"
  description          = "Main IAM role for SSM"
  path                 = "/"
  max_session_duration = 3600
  prefix               = local.prefix
  policy               = []
  policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  ]
  trust_policy = [
    {
      sid     = "Trust"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals = {
        type        = "Service"
        identifiers = ["ec2.amazonaws.com"]
      }
      conditions = []
    }
  ]
}

module "ssm_sg" {
  source      = "../../modules/sg"
  sg_name     = "ssm-sg"
  description = "Main Security Group of SSM in ${local.prefix}"
  vpc_id      = null
  prefix      = local.prefix
  egress = {
    "allow_all" = {
      cidr_ipv4   = "0.0.0.0/0"
      ip_protocol = "-1"
    }
  }
}

module "quarantine_sg" {
  source      = "../../modules/sg"
  sg_name     = "quarantine-sg"
  description = "Quarantined SG"
  vpc_id      = null
  ingress     = {}
  egress      = {}
  prefix      = local.prefix
}

module "event_bus" {
  source         = "../../modules/eventbridge_bus"
  event_bus_name = var.event_bus_name
  description    = "Central Aegis Bus for lambda automation"
  kms_key_arn    = module.main_key.key_arn
  prefix         = local.prefix
}

module "ssh_rdp_function" {
  source                      = "../../modules/lambda"
  function_name               = "ssh_rdp_function"
  runtime                     = "python3.14"
  memory_size                 = 256
  timeout                     = 30
  log_format                  = "JSON"
  deletion_protection_enabled = false
  log_group_class             = "STANDARD"
  retention_in_days           = 7
  target_role_arns            = var.target_role_arns
  sns_topic_arn               = module.sns_medium.topic_arn
  kms_key_arn                 = module.main_key.key_arn
  prefix                      = local.prefix
  trigger = {
    statement_id = "AllowExecutionFromEventBridge"
    action       = "lambda:InvokeFunction"
    principal    = "events.amazonaws.com"
    source_arn   = module.ssh_rdp_event_rule.rule_arn
  }
  lambda_environment_variables = {
    "REGION"           = var.region
    "SNS_TOPIC_ARN"    = module.sns_medium.topic_arn
    "TARGET_ROLE_ARNS" = jsonencode(var.target_role_arns)
  }
  extra_statements = [
    {
      sid    = "SecurityGroups"
      effect = "Allow"
      actions = [
        "ec2:DescribeSecurityGroups",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:CreateTags"
      ]
      resources = ["*"]
    }
  ]
}

module "ssh_rdp_event_rule" {
  source         = "../../modules/eventbridge_rule"
  state          = "ENABLED"
  rule_name      = "ssh-rdp-rule"
  target_id      = "ToLambda"
  event_bus_name = null
  target_arn     = module.ssh_rdp_function.function_arn
  prefix         = local.prefix
  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
    }
  })
}

module "central_cloudwatch_dashboard" {
  source         = "../../modules/cloudwatch_dashboard"
  prefix         = local.prefix
  dashboard_name = "central-dashboard"
  region         = var.region

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 18
        height = 9
        properties = {
          title  = "Lambda Automation Overview"
          view   = "timeSeries"
          period = 300
          region = var.region
          stat   = "Sum"
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", module.ssh_rdp_function.function_name],
            [".", "Errors", ".", "."],
            [".", "Throttles", ".", "."]
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 0
        width  = 6
        height = 2
        properties = {
          title                = "Lambda Errors"
          view                 = "singleValue"
          region               = var.region
          period               = 300
          stat                 = "Sum"
          sparkline            = true
          setPeriodToTimeRange = true
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", module.ssh_rdp_function.function_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 2
        width  = 6
        height = 2
        properties = {
          title                = "Lambda Throttles"
          view                 = "singleValue"
          region               = var.region
          period               = 300
          stat                 = "Sum"
          sparkline            = true
          setPeriodToTimeRange = true
          metrics = [
            ["AWS/Lambda", "Throttles", "FunctionName", module.ssh_rdp_function.function_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 4
        width  = 6
        height = 4
        properties = {
          title  = "Lambda Duration vs Timeout"
          view   = "gauge"
          region = var.region
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", module.ssh_rdp_function.function_name]
          ]
          yAxis = {
            left = {
              min = 0
              max = 60000
            }
          }
          annotations = {
            horizontal = [
              {
                value = 45000
                label = "Warning"
              },
              {
                value = 60000
                label = "Timeout"
              }
            ]
          }
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 8
        width  = 18
        height = 6
        properties = {
          title  = "SNS Alerts Overview"
          view   = "timeSeries"
          period = 300
          region = var.region
          stat   = "Sum"
          metrics = [
            ["AWS/SNS", "NumberOfMessagesPublished", "TopicName", module.sns_medium.topic_name],
            [".", "NumberOfNotificationsDelivered", ".", "."],
            [".", "NumberOfNotificationsFailed", ".", "."]
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 8
        width  = 6
        height = 3
        properties = {
          title                = "SNS Delivered"
          view                 = "singleValue"
          region               = var.region
          period               = 300
          stat                 = "Sum"
          sparkline            = true
          setPeriodToTimeRange = true
          metrics = [
            ["AWS/SNS", "NumberOfNotificationsDelivered", "TopicName", module.sns_medium.topic_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 18
        y      = 11
        width  = 6
        height = 3
        properties = {
          title                = "SNS Failed"
          view                 = "singleValue"
          region               = var.region
          period               = 300
          stat                 = "Sum"
          sparkline            = true
          setPeriodToTimeRange = true
          metrics = [
            ["AWS/SNS", "NumberOfNotificationsFailed", "TopicName", module.sns_medium.topic_name]
          ]
        }
      }
    ]
  })
}

module "test_sg" {
  source  = "../../modules/sg"
  prefix  = local.prefix
  sg_name = "test-ssh-rdp"
  ingress = {
    "ssh_ipv4" = {
      cidr_ipv4   = "0.0.0.0/0"
      from_port   = 22
      to_port     = 22
      ip_protocol = "tcp"
    },
    "ssh_ipv6" = {
      cidr_ipv6   = "::/0"
      from_port   = 22
      to_port     = 22
      ip_protocol = "tcp"
    },
    "rdp_ipv4" = {
      cidr_ipv4   = "0.0.0.0/0"
      from_port   = 3389
      to_port     = 3389
      ip_protocol = "tcp"
    }
    "rdp_ipv6" = {
      cidr_ipv6   = "::/0"
      from_port   = 3389
      to_port     = 3389
      ip_protocol = "tcp"
    }
  }
  egress = {
    "Allow_all" = {
      ip_protocol = "-1"
      cidr_ipv4   = "0.0.0.0/0"
    }
  }

}