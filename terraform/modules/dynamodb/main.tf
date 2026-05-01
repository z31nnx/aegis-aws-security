resource "aws_dynamodb_table" "dynamodb" {
  name = "${var.prefix}-${var.table_name}"
  billing_mode = var.billing_mode
  read_capacity = var.read_capacity
  write_capacity = var.write_capacity
  hash_key = var.hash_key
  range_key = var.range_key
  deletion_protection_enabled = var.deletion_protection

  server_side_encryption {
    enabled = var.server_side_encryption.enabled
    kms_key_arn = var.server_side_encryption.kms_key_arn
  }

  ttl {
    enabled = var.ttl.enabled
    attribute_name = var.ttl.attribute_name
  }

  dynamic "attribute" {
    for_each = var.attribute
    iterator = att 

    content {
      name = att.value.name
      type = att.value.type
    }
  }
  tags = {
    Name = "${var.prefix}-${var.table_name}"
  }
}