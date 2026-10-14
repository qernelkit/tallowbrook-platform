# Account-wide EBS defaults and the bastion host.

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn = module.ebs_key.key_arn
}

data "aws_ami" "bastion" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["tb-bastion-*"]
  }
}

# The host key is generated here so its public half can be pinned in the ops
# known_hosts file before the instance ever boots.
resource "tls_private_key" "bastion_host" {
  algorithm = "ED25519"
}

resource "aws_secretsmanager_secret" "bastion_host_key" {
  name        = "bastion/host-key"
  description = "Bastion host key, installed by the bootstrap"
}

resource "aws_secretsmanager_secret_version" "bastion_host_key" {
  secret_id     = aws_secretsmanager_secret.bastion_host_key.id
  secret_string = tls_private_key.bastion_host.private_key_openssh
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "bastion" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.bastion_host_key.arn]
  }
}

resource "aws_iam_role" "bastion" {
  name               = "bastion"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "bastion" {
  name   = "bastion-bootstrap"
  role   = aws_iam_role.bastion.id
  policy = data.aws_iam_policy_document.bastion.json
}

resource "aws_iam_role_policy_attachment" "bastion_ssm" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "bastion" {
  name = "bastion"
  role = aws_iam_role.bastion.name
}

resource "aws_launch_template" "bastion" {
  name_prefix            = "bastion-"
  image_id               = data.aws_ami.bastion.id
  instance_type          = "t4g.small"
  vpc_security_group_ids = [aws_security_group.bastion.id]
  user_data              = base64encode(templatefile("${path.module}/templates/bastion-bootstrap.sh.tftpl", { region = var.region }))

  iam_instance_profile {
    name = aws_iam_instance_profile.bastion.name
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "bastion", Role = "bastion" }
  }
}

resource "aws_autoscaling_group" "bastion" {
  name                = "bastion"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = aws_subnet.public[*].id

  launch_template {
    id      = aws_launch_template.bastion.id
    version = "$Latest"
  }
}

output "bastion_host_public_key" {
  description = "Pinned in the ops known_hosts file for the bastion."
  value       = tls_private_key.bastion_host.public_key_openssh
}
