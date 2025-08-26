output "ssm_role_name" {
  value = aws_iam_role.ssm_role.name
}

output "ssm_role_arn" {
  value = aws_iam_role.ssm_role.arn
}

output "ssm_instance_profile_name" {
  value = aws_iam_instance_profile.ssm_instance_profile.name
}

output "ssm_instance_profile_arn" {
  value = aws_iam_instance_profile.ssm_instance_profile.arn
}

output "attached_policy_arns" {
  value = var.ssm_role_policies
}
