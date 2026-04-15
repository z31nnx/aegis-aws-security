data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = var.trust_policy
    iterator = policy
    content {
      sid     = policy.value.sid
      effect  = policy.value.effect
      actions = policy.value.actions
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

resource "aws_iam_role" "role" {
  name                 = "${var.prefix}-${var.role_name}"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.max_session_duration
  path                 = var.path

  tags = {
    Name = "${var.prefix}-${var.role_name}"
  }
}

data "aws_iam_policy_document" "policy" {
  count = length(var.policy) > 0 ? 1 : 0
  dynamic "statement" {
    for_each = var.policy
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
        for_each = policy.value.conditions
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

resource "aws_iam_role_policy" "role_policy" {
  count  = length(var.policy) > 0 ? 1 : 0
  name   = "${var.prefix}-${var.role_name}-inline"
  role   = aws_iam_role.role.name
  policy = data.aws_iam_policy_document.policy[0].json
}

resource "aws_iam_role_policy_attachment" "policy_attachment" {
  for_each = toset(var.policy_arns)

  role       = aws_iam_role.role.name
  policy_arn = each.value
}