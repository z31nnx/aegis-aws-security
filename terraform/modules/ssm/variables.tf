variable "name_prefix" {
  type = string
}
variable "ssm_role_name" {
  type = string
}
variable "ssm_instance_profile_name" {
  type = string
}
variable "ssm_role_policies" {
  type    = set(string)
  default = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"]
}
