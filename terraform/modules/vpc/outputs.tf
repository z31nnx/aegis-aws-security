output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_rt_id" {
  value = aws_route_table.private_rt.id
}