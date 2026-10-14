# SFTP drop for carriers that cannot use the EDI API. Files land in the exports
# bucket under carriers/<name>/.

resource "aws_security_group" "carrier_sftp" {
  name        = "carrier-sftp"
  description = "SFTP from carrier networks"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_eip" "carrier_sftp" {
  count  = 2
  domain = "vpc"
}

resource "aws_transfer_server" "carrier_sftp" {
  identity_provider_type = "SERVICE_MANAGED"
  protocols              = ["SFTP"]
  endpoint_type          = "VPC"
  security_policy_name   = "TransferSecurityPolicy-2025-03"
  logging_role           = aws_iam_role.carrier_sftp.arn

  endpoint_details {
    vpc_id                 = aws_vpc.main.id
    subnet_ids             = slice(aws_subnet.public[*].id, 0, 2)
    address_allocation_ids = aws_eip.carrier_sftp[*].id
    security_group_ids     = [aws_security_group.carrier_sftp.id]
  }
}

data "aws_iam_policy_document" "transfer_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["transfer.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "carrier_sftp" {
  name               = "carrier-sftp"
  assume_role_policy = data.aws_iam_policy_document.transfer_assume.json
}

resource "aws_transfer_user" "ridgeway" {
  server_id      = aws_transfer_server.carrier_sftp.id
  user_name      = "carrier-ridgeway"
  role           = aws_iam_role.carrier_sftp.arn
  home_directory = "/${aws_s3_bucket.exports.id}/carriers/ridgeway"
}
