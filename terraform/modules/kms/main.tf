resource "aws_kms_key" "key" {
  description             = var.description
  enable_key_rotation     = var.enable_key_rotation
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = data.aws_iam_policy_document.policy.json
}

resource "aws_kms_alias" "alias" {
  name          = "alias/${var.prefix}-${var.key_alias}"
  target_key_id = aws_kms_key.key.key_id
}

data "aws_iam_policy_document" "policy" {
  dynamic "statement" {
    for_each = var.key_policy
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
