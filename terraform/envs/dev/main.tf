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
}

module "kms" {
  source                  = "../../modules/kms"
  central_logs_bucket_arn = module.central-logging.central_logs_bucket_arn
  cloudtrail_name = var.cloudtrail_name
  region                  = var.region
  main_username           = var.main_username
  global_tags             = local.global_tags
}

module "central-logging" {
  source                   = "../../modules/central-logging"
  region                   = var.region
  central_bucket_name      = var.central_bucket_name
  central_logs_kms_key_arn = module.kms.central_logs_key_arn
  global_tags              = local.global_tags
}

module "cloudtrail" {
  source                   = "../../modules/cloudtrail"
  region                   = var.region
  central_logs_bucket_name = module.central-logging.central_logs_bucket_name
  central_logs_key_arn     = module.kms.central_logs_key_arn
  cloudtrail_name          = var.cloudtrail_name
  global_tags              = local.global_tags
}

module "config" {
  source                   = "../../modules/config"
  config_name              = var.config_name
  central_logs_bucket_name = module.central-logging.central_logs_bucket_name
  global_tags              = local.global_tags
}