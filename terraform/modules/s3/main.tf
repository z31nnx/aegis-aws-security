resource "aws_s3_bucket" "bucket" {
  bucket        = "${var.prefix}-${var.bucket_name}"
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = var.versioning
  }
}

resource "aws_s3_bucket_public_access_block" "bpa" {
  bucket                  = aws_s3_bucket.bucket.id
  block_public_acls       = var.public_access_block.block_public_acls
  block_public_policy     = var.public_access_block.block_public_policy
  ignore_public_acls      = var.public_access_block.ignore_public_acls
  restrict_public_buckets = var.public_access_block.restrict_public_buckets
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.server_side_encryption.kms_key_arn
      sse_algorithm     = var.server_side_encryption.sse_algorithm
    }
    bucket_key_enabled = var.server_side_encryption.bucket_key_enabled
  }
}

data "aws_iam_policy_document" "policy" {
  dynamic "statement" {
    for_each = var.bucket_policy
    iterator = policy
    content {
      sid       = policy.value.sid
      effect    = policy.value.effect
      actions   = policy.value.actions
      resources = policy.value.resources

      principals {
        type        = policy.value.principals.type
        identifiers = policy.value.principals.identifiers
      }

      dynamic "condition" {
        for_each = policy.value.conditions != null ? policy.value.conditions : []
        iterator = condition
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }

  }
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.policy.json
}