data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}


resource "aws_iam_role" "ssm_role" {
  name               = var.ssm_role_name
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_role_policy_attachment" {
  for_each = var.ssm_role_policies

  role       = aws_iam_role.ssm_role.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = var.ssm_instance_profile_name
  role = aws_iam_role.ssm_role.name
}
