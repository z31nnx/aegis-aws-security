locals {
  account_id = data.aws_caller_identity.me.account_id
  region = data.aws_region.current.region
  partition = data.aws_partition.current.partition
}