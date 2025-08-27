output "lambda_cloudtrail_tamper_arn" {
  value = aws_lambda_function.lambda_cloudtrail_tamper_function.arn
}
output "lambda_cloudtrail_tamper_exec_role_arn" {
  value = aws_iam_role.lambda_cloudtrail_tamper_exec_role.arn
}

output "lambda_cloudtrail_tamper_exec_role_name" {
  value = aws_iam_role.lambda_cloudtrail_tamper_exec_role.name
}