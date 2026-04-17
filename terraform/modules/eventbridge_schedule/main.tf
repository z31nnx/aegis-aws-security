data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "role" {
  name               = "${var.prefix}-${var.schedule_group_name}-schedule-role"
  assume_role_policy = data.aws_iam_policy_document.trust.json

  tags = {
    Name = "${var.prefix}-${var.schedule_group_name}-schedule-role"
  }
}

data "aws_iam_policy_document" "policy" {
  dynamic "statement" {
    for_each = var.role_policy
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
  name        = "${var.prefix}-${var.schedule_group_name}-scheduler-policy"
  description = "${var.prefix}-${var.schedule_group_name}-scheduler-policy"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_role_policy_attachment" "role_policy_attachment" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_scheduler_schedule" "schedule" {
  for_each = var.rules

  name                = "${var.prefix}-${each.key}"
  group_name          = var.schedule_group_name
  state               = each.value.state
  schedule_expression = each.value.schedule_expression

  target {
    arn      = each.value.target_arn
    role_arn = aws_iam_role.role.arn
  }

  flexible_time_window {
    mode = each.value.flexible_time_window
  }
}
