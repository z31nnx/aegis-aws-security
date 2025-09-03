data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "cloudtrail_tamper_function_permissions" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }

  # Manage the CloudTrail baseline: create/update selectors, start logging, read status
  statement {
    sid    = "CloudTrailManage"
    effect = "Allow"
    actions = [
      "cloudtrail:CreateTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:StartLogging",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:DescribeTrails",
      "cloudtrail:ListTrails",
      "cloudtrail:ListTags",
      "cloudtrail:AddTags",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:PutEventSelectors"
    ]
    resources = ["*"]
  }

  # Publish alerts
  statement {
    sid     = "Alerting"
    effect  = "Allow"
    actions = ["sns:Publish", "sns:GetTopicAttributes"]
    resources = [
      var.sns_alerts_high_arn
    ]
  }

  statement {
    sid       = "KMSTopicEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sns:topicArn"
      values   = [var.sns_alerts_high_arn]
    }
  }
}

resource "aws_iam_role" "cloudtrail_tamper_function_exec_role" {
  name               = "${var.name_prefix}-${var.cloudtrail_tamper_function_exec_role_name}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "cloudtrail_tamper_function_basic_logs" {
  role       = aws_iam_role.cloudtrail_tamper_function_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "cloudtrail_tamper_function_permissions" {
  name   = "${var.name_prefix}-${var.cloudtrail_tamper_function_exec_role_name}-policy"
  policy = data.aws_iam_policy_document.cloudtrail_tamper_function_permissions.json
}

resource "aws_iam_role_policy_attachment" "cloudtrail_tamper_attach" {
  role       = aws_iam_role.cloudtrail_tamper_function_exec_role.name
  policy_arn = aws_iam_policy.cloudtrail_tamper_function_permissions.arn
}

data "aws_iam_policy_document" "ssh_remediation_function_permissions" {
  # EC2 SG: read, revoke, tag
  statement {
    sid    = "EC2SecurityGroupOps"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:ModifySecurityGroupRules",
      "ec2:CreateTags"
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Alerting"
    effect    = "Allow"
    actions   = ["sns:Publish", "sns:GetTopicAttributes"]
    resources = [var.sns_alerts_high_arn]
  }

  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
  statement {
    sid       = "KMSTopicEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sns:topicArn"
      values   = [var.sns_alerts_high_arn]
    }
  }
}

resource "aws_iam_role_policy_attachment" "ssh_remediation_function_basic_logs" {
  role       = aws_iam_role.ssh_remediation_function_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "ssh_remediation_function_exec_role" {
  name               = "${var.name_prefix}-${var.ssh_remediation_function_exec_role_name}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_policy" "ssh_remediation_function_permissions" {
  name   = "${var.name_prefix}-${var.ssh_remediation_function_exec_role_name}-policy"
  policy = data.aws_iam_policy_document.ssh_remediation_function_permissions.json
}

resource "aws_iam_role_policy_attachment" "ssh_remediation_attach" {
  role       = aws_iam_role.ssh_remediation_function_exec_role.name
  policy_arn = aws_iam_policy.ssh_remediation_function_permissions.arn
}

data "aws_iam_policy_document" "lambda_crypto_permissions" {
  # Logs
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }

  # SNS (alerts) + KMS context for encrypted topic
  statement {
    sid       = "SNS"
    effect    = "Allow"
    actions   = ["sns:Publish", "sns:GetTopicAttributes"]
    resources = [var.sns_alerts_high_arn]
  }
  statement {
    sid       = "SNSKmsContext"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:aws:sns:topicArn"
      values   = [var.sns_alerts_high_arn]
    }
  }

  statement {
    sid    = "EC2Describe"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVolumes",
      "ec2:DescribeIamInstanceProfileAssociations"
    ]
    resources = ["*"]
  }

  # Network isolation + tagging
  statement {
    sid    = "EC2Isolation"
    effect = "Allow"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:CreateTags"
    ]
    resources = ["*"]
  }

  # Forensics + freeze + profile containment
  statement {
    sid       = "EC2Forensics"
    effect    = "Allow"
    actions   = ["ec2:CreateSnapshot", "ec2:CreateTags"]
    resources = ["*"]
  }
  statement {
    sid       = "EC2Freeze"
    effect    = "Allow"
    actions   = ["ec2:StopInstances"]
    resources = ["*"]
  }
  statement {
    sid       = "EC2ProfileContainment"
    effect    = "Allow"
    actions   = ["ec2:DisassociateIamInstanceProfile"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "crypto_quarantine_exec_role" {
  name               = "${var.name_prefix}-${var.crypto_quarantine_function_exec_role_name}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "crypto_quarantine_basic_logs" {
  role       = aws_iam_role.crypto_quarantine_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "lambda_crypto_permissions" {
  name   = "${var.name_prefix}-${var.crypto_quarantine_function_exec_role_name}-policy"
  policy = data.aws_iam_policy_document.lambda_crypto_permissions.json
}

resource "aws_iam_role_policy_attachment" "crypto_quarantine_attach" {
  role       = aws_iam_role.crypto_quarantine_exec_role.name
  policy_arn = aws_iam_policy.lambda_crypto_permissions.arn
}