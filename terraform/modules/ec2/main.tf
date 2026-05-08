resource "aws_instance" "instance" {
  ami                         = data.aws_ami.ami.image_id
  instance_type               = var.instance_type
  force_destroy               = var.force_destroy
  key_name                    = var.key_name
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.vpc_security_group_ids
  iam_instance_profile        = var.iam_instance_profile
  associate_public_ip_address = var.associate_public_ip_address

  metadata_options {
    http_tokens = var.metadata_http_tokens
  }

  root_block_device {
    encrypted = var.root_block_device_encrypted
  }

  tags = {
    Name = "${var.prefix}-${var.instance_name}"
  }
}