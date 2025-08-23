resource "aws_s3_bucket" "central_logs_bucket" {
  bucket = var.central_bucket_name

  tags = merge(local.global_tags)
}

resource "aws_s3_bucket_versioning" "central_logs_bucket_versioning" {
  bucket = aws_s3_bucket.central_logs_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "central_logs_bucket_sse" {
  bucket = aws_s3_bucket.central_logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.central_logs_kms_key
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "central_logs_bpa" {
  bucket                  = aws_s3_bucket.central_logs_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "central_logs_bucket" {
  statement {
    sid     = "AllowCloudTrailGetBucketAcl"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.central_logs_bucket.arn]
  }

  statement {
    sid     = "AllowCloudTrailListBucket"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.central_logs_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid     = "AllowCloudTrailPutObject"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.central_logs_bucket.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid     = "AllowConfigListBucket"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.central_logs_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "AllowConfigPutObject"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.central_logs_bucket.arn}/config/AWSLogs/${local.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "AllowCloudWatchLogsListBucket"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    resources = [aws_s3_bucket.central_logs_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "AllowCloudWatchLogsExport"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.central_logs_bucket.arn}/cwl-export/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "central_logs_bucket_policy" {
  bucket = aws_s3_bucket.central_logs_bucket.id
  policy = data.aws_iam_policy_document.central_logs_bucket.json
}