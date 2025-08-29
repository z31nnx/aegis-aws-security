output "lambda_cloudtrail_tamper_function_arn" {
  value = aws_lambda_function.lambda_cloudtrail_tamper_function.arn
}

output "lambda_cloudtrail_tamper_function_name" {
  value = aws_lambda_function.lambda_cloudtrail_tamper_function.function_name
}

output "lambda_cloudtrail_tamper_function_exec_role_arn" {
  value = aws_iam_role.lambda_cloudtrail_tamper_function_exec_role.arn
}

output "lambda_cloudtrail_tamper_function_exec_role_name" {
  value = aws_iam_role.lambda_cloudtrail_tamper_function_exec_role.name
}

output "lambda_ssh_remediation_function_arn" {
  value = aws_lambda_function.lambda_ssh_remediation_function.arn
}

output "lambda_ssh_remediation_function_name" {
  value = aws_lambda_function.lambda_ssh_remediation_function.function_name
}

output "lambda_ssh_remediation_function_exec_role_arn" {
  value = aws_iam_role.lambda_ssh_remediation_function_exec_role.arn
}

output "lambda_ssh_remediation_function_exec_role_name" {
  value = aws_iam_role.lambda_ssh_remediation_function_exec_role.name
}