output "eventbridge_bus_arn" {
  value = aws_cloudwatch_event_bus.bus.arn
}
output "eventbridge_bus_name" {
  value = aws_cloudwatch_event_bus.bus.name
}