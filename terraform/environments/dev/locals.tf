locals {
  global_tags = {
    project     = var.project
    environment = var.environment
    owner       = var.owner
    managedby   = var.managedby
  }
}