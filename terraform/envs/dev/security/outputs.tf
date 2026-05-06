output "ssm_instance_profile" {
  value = module.ssm_role.instance_profile_arn
}

output "sg_ids" {
  value = {
    ssm_sg = module.ssm_sg.sg_id
  }
}