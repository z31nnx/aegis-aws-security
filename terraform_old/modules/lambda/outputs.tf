output "cloudtrail_tamper" {
  value = {
    function_arn   = aws_lambda_function.cloudtrail_tamper_function.arn
    function_name  = aws_lambda_function.cloudtrail_tamper_function.function_name
    exec_role_arn  = aws_iam_role.cloudtrail_tamper_function_exec_role.arn
    exec_role_name = aws_iam_role.cloudtrail_tamper_function_exec_role.name
  }
}

output "ssh_remediation" {
  value = {
    function_arn   = aws_lambda_function.ssh_remediation_function.arn
    function_name  = aws_lambda_function.ssh_remediation_function.function_name
    exec_role_arn  = aws_iam_role.ssh_remediation_function_exec_role.arn
    exec_role_name = aws_iam_role.ssh_remediation_function_exec_role.name
  }
}

output "crypto_quarantine" {
  value = {
    function_arn   = aws_lambda_function.crypto_quarantine_function.arn
    function_name  = aws_lambda_function.crypto_quarantine_function.function_name
    exec_role_arn  = aws_iam_role.crypto_quarantine_exec_role.arn
    exec_role_name = aws_iam_role.crypto_quarantine_exec_role.name
  }
}