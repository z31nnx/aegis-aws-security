data "archive_file" "lambda_cloudtrail_tamper_zip" {
  type        = "zip"
  source_file = "${path.module}/../../lambda-functions/aegis_lambda_cloudtrail_tamper.py"
  output_path = "${path.module}/.build/aegis_lambda_cloudtrail_tamper_shield.zip"
}

resource "aws_lambda_function" "lambda_cloudtrail_tamper_function" {
  function_name    = "${var.name_prefix}-${var.lambda_cloudtrail_tamper_function_name}"
  role             = aws_iam_role.lambda_cloudtrail_tamper_function_exec_role.arn
  runtime          = "python3.13"
  handler          = "aegis_lambda_cloudtrail_tamper.lambda_handler"
  filename         = data.archive_file.lambda_cloudtrail_tamper_zip.output_path
  source_code_hash = data.archive_file.lambda_cloudtrail_tamper_zip.output_base64sha256
  timeout          = 30
  memory_size      = 256
  publish          = true

  environment {
    variables = {
      TRAIL_NAME     = "${var.cloudtrail_name}"
      LOG_BUCKET     = var.central_logs_bucket
      LOG_PREFIX     = "cloudtrail"
      KMS_KEY_ID     = var.kms_key_arn
      MULTI_REGION   = "true"
      INCLUDE_GLOBAL = "true"
      LOG_VALIDATION = "true"
      ORG_TRAIL      = "false"
      SNS_HIGH       = var.sns_alerts_high_arn

      BASELINE_TAGS_JSON = jsonencode({
        Project     = var.project
        Environment = var.environment
        Owner       = var.owner
        ManagedBy   = var.managedby
        Name        = var.cloudtrail_name
      })
    }
  }
}

data "archive_file" "lambda_ssh_remediation_zip" {
  type        = "zip"
  source_file = "${path.module}/../../lambda-functions/aegis_lambda_ssh_remediation.py"
  output_path = "${path.module}/.build/aegis_lambda_ssh_remediation.zip"
}

resource "aws_lambda_function" "lambda_ssh_remediation_function" {
  function_name    = "${var.name_prefix}-${var.lambda_ssh_remediation_function_name}"
  role             = aws_iam_role.lambda_ssh_remediation_function_exec_role.arn
  runtime          = "python3.13"
  handler          = "aegis_lambda_ssh_remediation.lambda_handler"
  filename         = data.archive_file.lambda_ssh_remediation_zip.output_path
  source_code_hash = data.archive_file.lambda_ssh_remediation_zip.output_base64sha256
  timeout          = 30
  memory_size      = 256
  publish          = true

  environment {
    variables = {
      SNS_HIGH = var.sns_alerts_high_arn
    }
  }
}