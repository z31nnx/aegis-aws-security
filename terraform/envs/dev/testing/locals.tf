locals {
  base_tags = {
    "Environment" = var.environment
    "Project"     = var.project
    "Owner"       = var.owner
    "ManagedBy"   = var.managedby
  }
  prefix = "${var.environment}-${var.project}"
}