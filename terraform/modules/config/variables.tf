variable "name_prefix" {}
variable "config_name" {}
variable "config_role_name" {}
variable "central_logs_bucket_name" {}

variable "config_rules" {
  type = list(object({
    name              = string
    source_identifier = string
  }))
  default = [
    {
      name              = "ec2-ebs-encryption-by-default"
      source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
    },
    {
      name              = "ec2-imdsv2-check"
      source_identifier = "EC2_IMDSV2_CHECK"
    },
    {
      name              = "restricted-common-ports"
      source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
    },
    {
      name              = "restricted-ssh"
      source_identifier = "INCOMING_SSH_DISABLED"
    },
    {
      name              = "s3-bucket-level-public-access-prohibited"
      source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    },
    {
      name              = "cloudtrail-enabled"
      source_identifier = "CLOUD_TRAIL_ENABLED"
    },
    {
      name              = "iam-user-mfa-enabled"
      source_identifier = "IAM_USER_MFA_ENABLED"
    }
  ]
}