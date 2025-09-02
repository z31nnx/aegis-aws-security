resource "aws_vpc_endpoint" "flow_log" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [var.private_rt_id]

  tags = {
    Name = "${var.name_prefix}-s3-gateway-endpoint"
  }
}