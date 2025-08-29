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

data "aws_iam_policy_document" "lambda_cloudtrail_tamper_function_permissions" {
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

resource "aws_iam_role" "lambda_cloudtrail_tamper_function_exec_role" {
  name               = "${var.name_prefix}-${var.lambda_cloudtrail_tamper_function_exec_role_name}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

# Basic logs for Lambda
resource "aws_iam_role_policy_attachment" "lambda_cloudtrail_tamper_function_basic_logs" {
  role       = aws_iam_role.lambda_cloudtrail_tamper_function_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "lambda_cloudtrail_tamper_function_permissions" {
  name   = "${var.name_prefix}-${var.lambda_cloudtrail_tamper_function_exec_role_name}-policy"
  policy = data.aws_iam_policy_document.lambda_cloudtrail_tamper_function_permissions.json
}

resource "aws_iam_role_policy_attachment" "lambda_cloudtrail_tamper_attach" {
  role       = aws_iam_role.lambda_cloudtrail_tamper_function_exec_role.name
  policy_arn = aws_iam_policy.lambda_cloudtrail_tamper_function_permissions.arn
}

data "aws_iam_policy_document" "lambda_ssh_remediation_function_permissions" {
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

resource "aws_iam_role_policy_attachment" "lambda_ssh_remediation_function_basic_logs" {
  role       = aws_iam_role.lambda_ssh_remediation_function_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role" "lambda_ssh_remediation_function_exec_role" {
  name               = "${var.name_prefix}-${var.lambda_ssh_remediation_function_exec_role_name}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_policy" "lambda_ssh_remediation_function_permissions" {
  name   = "${var.name_prefix}-${var.lambda_ssh_remediation_function_exec_role_name}-policy"
  policy = data.aws_iam_policy_document.lambda_ssh_remediation_function_permissions.json
}

resource "aws_iam_role_policy_attachment" "lambda_ssh_guard_attach" {
  role       = aws_iam_role.lambda_ssh_remediation_function_exec_role.name
  policy_arn = aws_iam_policy.lambda_ssh_remediation_function_permissions.arn
}