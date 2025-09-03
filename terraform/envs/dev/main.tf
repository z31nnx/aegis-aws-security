terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      Owner       = var.owner
      ManagedBy   = var.managedby
    }
  }
}

module "ebs" {
  source = "../../modules/ebs"
}

module "guardduty" {
  source = "../../modules/guardduty"
  region = var.region
}

module "security_hub" {
  source = "../../modules/security_hub"
}

module "sg" {
  source             = "../../modules/sg"
  name_prefix        = local.name_prefix
  quarantine_sg_name = var.quarantine_sg_name
}

module "ssm" {
  source                    = "../../modules/ssm"
  ssm_role_name             = var.ssm_role_name
  ssm_instance_profile_name = var.ssm_instance_profile_name
  name_prefix               = local.name_prefix
}

module "sns" {
  source      = "../../modules/sns"
  sns_emails  = var.sns_emails
  kms_key_arn = module.kms.central_logs_key_arn
  name_prefix = local.name_prefix
}

module "central_logging" {
  source                   = "../../modules/central_logging"
  central_bucket_name      = var.central_bucket_name
  central_logs_kms_key_arn = module.kms.central_logs_key_arn
  name_prefix              = local.name_prefix
}

module "kms" {
  source                  = "../../modules/kms"
  cloudtrail_name         = var.cloudtrail_name
  main_username           = var.main_username
  kms_key_alias           = var.kms_key_alias
  central_logs_bucket_arn = module.central_logging.central_logs_bucket_arn
  name_prefix             = local.name_prefix
}


module "cloudtrail" {
  source                   = "../../modules/cloudtrail"
  cloudtrail_name          = var.cloudtrail_name
  central_logs_bucket_name = module.central_logging.central_logs_bucket_name
  central_logs_key_arn     = module.kms.central_logs_key_arn
  name_prefix              = local.name_prefix
}

module "config" {
  source                   = "../../modules/config"
  config_name              = var.config_name
  config_role_name         = var.config_role_name
  central_logs_bucket_name = module.central_logging.central_logs_bucket_name
  name_prefix              = local.name_prefix
}

module "lambda" {
  source                                           = "../../modules/lambda"
  lambda_cloudtrail_tamper_function_name           = var.lambda_cloudtrail_tamper_function_name
  lambda_cloudtrail_tamper_function_exec_role_name = var.lambda_cloudtrail_tamper_function_exec_role_name
  lambda_ssh_remediation_function_name             = var.lambda_ssh_remediation_function_name
  lambda_ssh_remediation_function_exec_role_name   = var.lambda_ssh_remediation_function_exec_role_name
  lambda_crypto_quarantine_function_name           = var.lambda_crypto_quarantine_function_name
  lambda_crypto_quarantine_function_exec_role_name = var.lambda_crypto_quarantine_function_exec_role_name
  sns_alerts_high_arn                              = module.sns.sns_alerts_high_topic_arn
  sns_alerts_medium_arn                            = module.sns.sns_alerts_medium_topic_arn
  central_logs_bucket                              = module.central_logging.central_logs_bucket_name
  cloudtrail_name                                  = module.cloudtrail.cloudtrail_trail_name
  kms_key_arn                                      = module.kms.central_logs_key_arn
  quarantine_sg_id                                 = module.sg.quarantine_sg_id
  name_prefix                                      = local.name_prefix
  project                                          = var.project
  environment                                      = var.environment
  owner                                            = var.owner
  managedby                                        = var.managedby
}

module "eventbridge" {
  source                                        = "../../modules/eventbridge"
  lambda_cloudtrail_tamper_shield_function_arn  = module.lambda.lambda_cloudtrail_tamper_function_arn
  lambda_cloudtrail_tamper_shield_function_name = module.lambda.lambda_cloudtrail_tamper_function_name
  lambda_ssh_remediation_function_arn           = module.lambda.lambda_ssh_remediation_function_arn
  lambda_ssh_remediation_function_name          = module.lambda.lambda_ssh_remediation_function_name
  lambda_crypto_quarantine_function_arn         = module.lambda.lambda_crypto_quarantine_function_arn
  lambda_crypto_quarantine_function_name        = module.lambda.lambda_crypto_quarantine_function_name
  cloudtrail_name                               = module.cloudtrail.cloudtrail_trail_name
  cloudtrail_arn                                = module.cloudtrail.cloudtrail_trail_arn
  name_prefix                                   = local.name_prefix
}
