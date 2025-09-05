data "archive_file" "cloudtrail_tamper_zip" {
  type        = "zip"
  source_file = "${path.module}/../../lambda-functions/cloudtrail_tamper.py"
  output_path = "${path.module}/.build/cloudtrail_tamper.zip"
}

resource "aws_lambda_function" "cloudtrail_tamper_function" {
  function_name    = "${var.name_prefix}-${var.cloudtrail_tamper_function_name}"
  role             = aws_iam_role.cloudtrail_tamper_function_exec_role.arn
  runtime          = "python3.13"
  handler          = "cloudtrail_tamper.lambda_handler"
  filename         = data.archive_file.cloudtrail_tamper_zip.output_path
  source_code_hash = data.archive_file.cloudtrail_tamper_zip.output_base64sha256
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

  dead_letter_config {
    target_arn = var.aegis_lambda_dlq_arn
  }
}

data "archive_file" "ssh_remediation_zip" {
  type        = "zip"
  source_file = "${path.module}/../../lambda-functions/ssh_remediation.py"
  output_path = "${path.module}/.build/ssh_remediation.zip"
}

resource "aws_lambda_function" "ssh_remediation_function" {
  function_name    = "${var.name_prefix}-${var.ssh_remediation_function_name}"
  role             = aws_iam_role.ssh_remediation_function_exec_role.arn
  runtime          = "python3.13"
  handler          = "ssh_remediation.lambda_handler"
  filename         = data.archive_file.ssh_remediation_zip.output_path
  source_code_hash = data.archive_file.ssh_remediation_zip.output_base64sha256
  timeout          = 30
  memory_size      = 256
  publish          = true

  environment {
    variables = {
      SNS_MED = var.sns_alerts_medium_arn
    }
  }

  dead_letter_config {
    target_arn = var.aegis_lambda_dlq_arn
  }
}

data "archive_file" "crypto_quarantine_zip" {
  type        = "zip"
  source_file = "${path.module}/../../lambda-functions/crypto_quarantine.py"
  output_path = "${path.module}/.build/crypto_quarantine.zip"
}

resource "aws_lambda_function" "crypto_quarantine_function" {
  function_name    = "${var.name_prefix}-${var.crypto_quarantine_function_name}"
  role             = aws_iam_role.crypto_quarantine_exec_role.arn
  runtime          = "python3.13"
  handler          = "crypto_quarantine.lambda_handler"
  filename         = data.archive_file.crypto_quarantine_zip.output_path
  source_code_hash = data.archive_file.crypto_quarantine_zip.output_base64sha256
  timeout          = 60
  memory_size      = 256
  publish          = true

  environment {
    variables = {
      SNS_HIGH        = var.sns_alerts_high_arn
      FINDING_PREFIX  = "CryptoCurrency:EC2/"
      STOP_INSTANCE   = "true"
      DETACH_PROFILE  = "true"
      TAKE_SNAPSHOTS  = "true"
      ISOLATION_SG_ID = var.quarantine_sg_id # leave blank so code auto-creates Aegis-Isolation-SG
    }
  }

  dead_letter_config {
    target_arn = var.aegis_lambda_dlq_arn
  }
}