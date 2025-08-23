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

module "keys" {
  source        = "../../modules/keys"
  main_username = var.main_username
  global_tags   = local.global_tags
}

module "central-logging" {
  source               = "../../modules/central-logging"
  central_bucket_name  = var.central_bucket_name
  central_logs_kms_key = module.keys.central_logs_key_arn
  global_tags          = local.global_tags
}