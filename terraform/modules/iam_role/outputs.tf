output "role_arn" {
  value = aws_iam_role.role.arn
}
output "instance_profile_arn" {
  value = aws_iam_instance_profile.profile.arn
}