locals {
  base_tags = {
    Environment = var.environment
    Project     = var.project
    Owner       = var.owner
    ManagedBy   = var.managedby
  }

  prefix = "${var.environment}-${var.project}"

  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  bucket_arn = module.central-logs-bucket.bucket_arn
}