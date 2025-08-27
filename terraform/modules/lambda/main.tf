data "archive_file" "lambda_cloudtrail_tamper_zip" {
  type        = "zip"
  source_file = "${path.module}/../../lambda-functions/lambda_cloudtrail_tamper.py"
  output_path = "${path.module}/.build/aegis-lambda-cloudtrail-tamper-shield.zip"
}

resource "aws_lambda_function" "lambda_cloudtrail_tamper_function" {
  function_name    = var.lambda_cloudtrail_tamper_function_name
  role             = aws_iam_role.lambda_cloudtrail_tamper_exec_role.arn
  runtime          = "python3.13"
  handler          = "lambda_cloudtrail_tamper.lambda_handler"
  filename         = data.archive_file.lambda_cloudtrail_tamper_zip.output_path
  source_code_hash = data.archive_file.lambda_cloudtrail_tamper_zip.output_base64sha256
  timeout          = 30
  memory_size      = 256
  publish          = true

  environment {
    variables = {
      TRAIL_NAME     = var.cloudtrail_name
      LOG_BUCKET     = var.central_logs_bucket
      LOG_PREFIX     = "cloudtrail"
      KMS_KEY_ID     = var.kms_key_arn
      MULTI_REGION   = "true"
      INCLUDE_GLOBAL = "true"
      LOG_VALIDATION = "true"
      ORG_TRAIL      = "false"
      SNS_HIGH       = var.sns_alerts_high_arn
    }
  }

  tags = local.global_tags
}


resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.lambda_cloudtrail_tamper_function.function_name}"
  retention_in_days = 30
  tags              = local.global_tags
}