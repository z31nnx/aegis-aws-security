data "terraform_remote_state" "security" {
  backend = "local"
  config = {
    path = "../security/terraform.tfstate"
  }
}

module "" {
  
}

module "test_instance" {
  source = "../../../modules/ec2"
  instance_name = "crypto-test"
  instance_type = "t3.micro"
  force_destroy = false 
  associate_public_ip_address = true 
  key_name = null 
  subnet_id = null
  prefix = local.prefix
  vpc_security_group_ids = [ data.terraform_remote_state.security.outputs.sg_ids.ssm_sg ]
  iam_instance_profile = data.terraform_remote_state.security.outputs.ssm_instance_profile

}