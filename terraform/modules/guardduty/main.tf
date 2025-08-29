resource "aws_guardduty_detector" "aegis_guardduty" {
  enable = true
  region = var.region
}

resource "aws_guardduty_detector_feature" "aegis_detector_s3" {
  detector_id = aws_guardduty_detector.aegis_guardduty.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# EKS audit logs (control-plane)
resource "aws_guardduty_detector_feature" "eks_audit" {
  detector_id = aws_guardduty_detector.aegis_guardduty.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

# Runtime monitoring (EKS/EC2/ECS-Fargate)
resource "aws_guardduty_detector_feature" "runtime" {
  detector_id = aws_guardduty_detector.aegis_guardduty.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  # add-ons
  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# EBS Malware Protection
resource "aws_guardduty_detector_feature" "ebs" {
  detector_id = aws_guardduty_detector.aegis_guardduty.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

# RDS login activity
resource "aws_guardduty_detector_feature" "rds_login" {
  detector_id = aws_guardduty_detector.aegis_guardduty.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Lambda network logs
resource "aws_guardduty_detector_feature" "lambda_net" {
  detector_id = aws_guardduty_detector.aegis_guardduty.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}