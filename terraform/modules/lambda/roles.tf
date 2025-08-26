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

resource "aws_iam_role" "lambda_cloudtrail_tamper_exec_role" {
  name               = var.lambda_cloudtrail_tamper_exec_role_name
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.global_tags
}

# Basic logs for Lambda
resource "aws_iam_role_policy_attachment" "lambda_cloudtrail_tamper_basic_logs" {
  role       = aws_iam_role.lambda_cloudtrail_tamper_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "lambda_cloudtrail_tamper_permissions" {
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
      "cloudtrail:GetEventSelectors",
      "cloudtrail:PutEventSelectors"
    ]
    resources = ["*"]
  }

  # Publish alerts
  statement {
    sid     = "Alerting"
    effect  = "Allow"
    actions = ["sns:Publish"]
    resources = [
      var.sns_alerts_high_arn,
      var.sns_alerts_medium_arn
    ]
  }
}

resource "aws_iam_policy" "lambda_cloudtrail_tamper_permissions" {
  name   = "${var.lambda_cloudtrail_tamper_exec_role_name}-policy"
  policy = data.aws_iam_policy_document.lambda_cloudtrail_tamper_permissions.json
}

resource "aws_iam_role_policy_attachment" "lambda_cloudtrail_tamper_attach" {
  role       = aws_iam_role.lambda_cloudtrail_tamper_exec_role.name
  policy_arn = aws_iam_policy.lambda_cloudtrail_tamper_permissions.arn
}