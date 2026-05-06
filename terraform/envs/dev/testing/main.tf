data "terraform_remote_state" "security" {
  backend = "local"
  config = {
    path = "../security/"
  }
}

module "test_instance" {
  source = "../../../modules/ec2"
  instance_name = "crypto-test"
  force_destroy = false 
  associate_public_ip_address = true 
  iam_instance_profile = 
}