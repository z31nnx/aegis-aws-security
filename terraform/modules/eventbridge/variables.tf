variable "name_prefix" {
    type = string
}
variable "cloudtrail_name" {
    type = module
}
variable "cloudtrail_arn" {
    type = module
}
variable "cloudtrail_tamper_function_arn" {
    type = module
}
variable "cloudtrail_tamper_function_name" {
    type = module
}
variable "ssh_remediation_function_arn" {
    type = module
}
variable "ssh_remediation_function_name" {
    type = module
}
variable "crypto_quarantine_function_arn" {
    type = module
}
variable "crypto_quarantine_function_name" {
    type = module
}

