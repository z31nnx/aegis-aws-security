output "role_arn" {
  value = aws_iam_role.role.arn
}
output "instance_profile_name" {
  value = aws_iam_instance_profile.profile.name
}