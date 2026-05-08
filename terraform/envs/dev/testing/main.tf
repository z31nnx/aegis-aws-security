data "terraform_remote_state" "security" {
  backend = "local"
  config = {
    path = "../security/terraform.tfstate"
  }
}

module "test_sg" {
  source      = "../../../modules/sg"
  sg_name     = "test-ssh-rdp-sg"
  description = "test for lambda"
  vpc_id      = null
  ingress = {
    "ssh_ipv4" = {
      cidr_ipv4   = "0.0.0.0/0"
      from_port   = 22
      to_port     = 22
      ip_protocol = "tcp"
    },
    "ssh_ipv6" = {
      cidr_ipv6   = "::/0"
      from_port   = 22
      to_port     = 22
      ip_protocol = "tcp"
    },
    "rdp_ipv4" = {
      cidr_ipv4   = "0.0.0.0/0"
      from_port   = 3389
      to_port     = 3389
      ip_protocol = "tcp"
    },
    "rdp_ipv6" = {
      cidr_ipv6   = "::/0"
      from_port   = 3389
      to_port     = 3389
      ip_protocol = "tcp"
    }
    egress = {
      cidr_ipv4   = "0.0.0.0/0"
      ip_protocol = "-1"
    }
  }
  prefix = local.prefix
  extra_tags = {
    Purpose = "test"
  }
}

module "test_instance" {
  source                      = "../../../modules/ec2"
  instance_name               = "crypto-test"
  instance_type               = "t3.micro"
  force_destroy               = false
  associate_public_ip_address = true
  key_name                    = null
  subnet_id                   = null
  prefix                      = local.prefix
  vpc_security_group_ids      = [data.terraform_remote_state.security.outputs.sg_ids.ssm_sg]
  iam_instance_profile        = data.terraform_remote_state.security.outputs.ssm_instance_profile
}

module "test_instance_2" {
  source                      = "../../../modules/ec2"
  instance_name               = "crypto-test-2"
  instance_type               = "t3.micro"
  force_destroy               = false
  associate_public_ip_address = true
  key_name                    = null
  subnet_id                   = null
  prefix                      = local.prefix
  vpc_security_group_ids      = [data.terraform_remote_state.security.outputs.sg_ids.ssm_sg]
  iam_instance_profile        = data.terraform_remote_state.security.outputs.ssm_instance_profile
}

module "test_instance_3" {
  source                      = "../../../modules/ec2"
  instance_name               = "crypto-test-3"
  instance_type               = "t3.micro"
  force_destroy               = false
  associate_public_ip_address = true
  key_name                    = null
  subnet_id                   = null
  prefix                      = local.prefix
  vpc_security_group_ids      = [data.terraform_remote_state.security.outputs.sg_ids.ssm_sg]
  iam_instance_profile        = data.terraform_remote_state.security.outputs.ssm_instance_profile
}