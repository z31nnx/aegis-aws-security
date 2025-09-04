output "cloudtrail_tamper_function_arn" {
  value = aws_lambda_function.cloudtrail_tamper_function.arn
}

output "cloudtrail_tamper_function_name" {
  value = aws_lambda_function.cloudtrail_tamper_function.function_name
}

output "cloudtrail_tamper_function_exec_role_arn" {
  value = aws_iam_role.cloudtrail_tamper_function_exec_role.arn
}

output "cloudtrail_tamper_function_exec_role_name" {
  value = aws_iam_role.cloudtrail_tamper_function_exec_role.name
}

output "ssh_remediation_function_arn" {
  value = aws_lambda_function.ssh_remediation_function.arn
}

output "ssh_remediation_function_name" {
  value = aws_lambda_function.ssh_remediation_function.function_name
}

output "ssh_remediation_function_exec_role_arn" {
  value = aws_iam_role.ssh_remediation_function_exec_role.arn
}

output "ssh_remediation_function_exec_role_name" {
  value = aws_iam_role.ssh_remediation_function_exec_role.name
}

output "crypto_quarantine_function_arn" {
  value = aws_lambda_function.crypto_quarantine_function.arn
}
output "crypto_quarantine_function_name" {
  value = aws_lambda_function.crypto_quarantine_function.function_name
}
output "crypto_quarantine_function_exec_role_arn" {
  value = aws_iam_role.crypto_quarantine_exec_role.arn
}
output "crypto_quarantine_function_exec_role_name" {
  value = aws_iam_role.crypto_quarantine_exec_role.name
}