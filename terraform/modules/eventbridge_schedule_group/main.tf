resource "aws_scheduler_schedule_group" "group" {
  name = "${var.prefix}-${var.schedule_group_name}"

  tags = {
    Name = "${var.prefix}-${var.schedule_group_name}"
  }
}