locals {
  region    = data.aws_region.current.region
  partition = data.aws_partition.current.partition
  standards = {
    afsbp = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
    cis14 = "arn:${local.partition}:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  }
  product_subscriptions = {
    guardduty = "arn:${local.partition}:securityhub:${local.region}::product/aws/guardduty"
    inspector = "arn:${local.partition}:securityhub:${local.region}::product/aws/inspector"
  }
}