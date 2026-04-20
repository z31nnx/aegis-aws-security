data "archive_file" "zip" {
  type        = "zip"
  source_file = "../../lambda-functions/${var.function_name}.py"
  output_path = "../../lambda-functions/.build/${var.function_name}.zip"
}

data "aws_iam_policy_document" "assume" {
  statement {
    sid     = "Trust"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_group" "log_group" {
  name              = "/aws/lambda/${var.prefix}-${var.function_name}"
  retention_in_days = var.retention_in_days
  log_group_class   = var.log_group_class

  tags = {
    Name = "/aws/lambda/${var.prefix}-${var.function_name}"
  }
}

resource "aws_iam_role" "role" {
  name               = "${var.function_name}-lambda-execution-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = {
    Name = "${var.function_name}-lambda-execution-role"
  }
}

data "aws_iam_policy_document" "policy" {
  dynamic "statement" {
    for_each = length(var.target_role_arns) > 0 ? [1] : []
    content {
      sid       = "MultiAccountRemediation"
      effect    = "Allow"
      actions   = ["sts:AssumeRole"]
      resources = var.target_role_arns
    }
  }

  statement {
    sid       = "CreateLogGroup"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup"]
    resources = ["*"]
  }

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.log_group.arn}:*"]
  }

  statement {
    sid       = "UseKMSForEncryptedSNS"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    sid       = "PublishToAlertsTopic"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  dynamic "statement" {
    for_each = var.extra_statements
    iterator = statement

    content {
      sid       = statement.value.sid
      effect    = statement.value.effect
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

resource "aws_iam_policy" "policy" {
  name        = "${var.function_name}-lambda-policy"
  description = "${var.function_name}-lambda-policy"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role_policy_attachment" "role_policy_attachment" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_lambda_function" "function" {
  filename         = data.archive_file.zip.output_path
  source_code_hash = data.archive_file.zip.output_base64sha256
  function_name    = "${var.prefix}-${var.function_name}"
  role             = aws_iam_role.role.arn
  handler          = "${var.function_name}.lambda_handler"
  runtime          = var.runtime
  timeout          = var.timeout
  memory_size      = var.memory_size
  publish          = true

  logging_config {
    log_format = var.log_format
    log_group  = aws_cloudwatch_log_group.log_group.name
  }

  environment {
    variables = var.lambda_environment_variables
  }
}