data "aws_caller_identity" "me" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

resource "aws_sqs_queue" "aegis_lambda_dlq" {
  name                      = "${var.name_prefix}-${var.dlq_name}"
  message_retention_seconds = 1209600 # 14 days (max for SQS)
  kms_master_key_id         = var.kms_key_arn

  tags = {
    Name = "${var.name_prefix}-${var.dlq_name}"
  }

}

data "aws_iam_policy_document" "aegis_lambda_dlq_policy" {
  statement {
    sid     = "AllowLambdaServiceToSend"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    resources = [aws_sqs_queue.aegis_lambda_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-*"]
    }
  }
}

resource "aws_sqs_queue_policy" "aegis_lambda_dlq_policy" {
  queue_url = aws_sqs_queue.aegis_lambda_dlq.id
  policy    = data.aws_iam_policy_document.aegis_lambda_dlq_policy.json
}