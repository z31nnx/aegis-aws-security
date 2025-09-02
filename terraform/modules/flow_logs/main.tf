resource "aws_flow_log" "vpc_flow_log" {
    log_destination = var.central_logs_bucket_arn
    log_destination_type = "s3"
    traffic_type = "ALL"
    vpc_id = var.vpc_id
    max_aggregation_interval = 60

    tags = {
        Name = "${var.name_prefix}-${var.flow_log_name}"
    }
}