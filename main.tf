data "aws_partition" "current" {}

locals {
  security_group_ids = flatten([var.vpc_security_group_ids != null ? var.vpc_security_group_ids : [], aws_security_group.this[0].id != null ? [aws_security_group.this[0].id] : []])
}

################################################################################
# Instance
################################################################################
resource "aws_instance" "this" {
  ami           = var.ami
  instance_type = var.instance_type
  hibernation   = var.hibernation

  user_data                   = var.user_data
  user_data_base64            = var.user_data_base64
  user_data_replace_on_change = var.user_data_replace_on_change

  availability_zone      = var.availability_zone
  subnet_id              = var.subnet_id
  vpc_security_group_ids = local.security_group_ids

  key_name             = var.create_new_key != null ? aws_key_pair.this[0].key_name : var.key_name
  monitoring           = var.monitoring
  get_password_data    = var.get_password_data
  iam_instance_profile = var.create_iam_instance_profile ? aws_iam_instance_profile.this[0].name : var.iam_instance_profile

  associate_public_ip_address = var.associate_public_ip_address
  private_ip                  = var.private_ip
  secondary_private_ips       = var.secondary_private_ips
  ipv6_address_count          = var.ipv6_address_count
  ipv6_addresses              = var.ipv6_addresses

  dynamic "network_interface" {
    for_each = var.network_interface

    content {
      device_index          = network_interface.value.device_index
      network_interface_id  = lookup(network_interface.value, "network_interface_id", null)
      delete_on_termination = try(network_interface.value.delete_on_termination, false)
    }
  }

  source_dest_check                    = length(var.network_interface) > 0 ? null : var.source_dest_check
  disable_api_termination              = var.disable_api_termination
  disable_api_stop                     = var.disable_api_stop
  instance_initiated_shutdown_behavior = var.instance_initiated_shutdown_behavior
  placement_group                      = var.placement_group
  tenancy                              = var.tenancy
  host_id                              = var.host_id

  tags        = merge({ "Name" = var.name }, var.instance_tags, var.custom_tags)
  volume_tags = var.enable_volume_tags ? merge({ "Name" = var.name }, var.volume_tags) : null
  lifecycle {
    ignore_changes = [
      ami
    ]
  }
}

################################################################################
# Security group
################################################################################

resource "aws_security_group" "this" {
  count       = var.security_group != null ? 1 : 0
  name        = "${var.name}-sg"
  description = "${var.name} network security group"
  vpc_id      = var.vpc_id

  ingress {
    description      = var.security_group.ingress.description
    from_port        = var.security_group.ingress.from_port
    to_port          = var.security_group.ingress.to_port
    protocol         = var.security_group.ingress.protocol
    cidr_blocks      = var.security_group.ingress.cidr_blocks
    ipv6_cidr_blocks = var.security_group.ingress.ipv6_cidr_blocks
  }

  dynamic "egress" {
    for_each = var.security_group.egress != null ? [] : [1]
    content {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }

  }
  dynamic "egress" {
    for_each = var.security_group.egress  != null ? [1] : []
    content {
      description      = var.security_group.egress.description
      from_port        = var.security_group.egress.from_port
      to_port          = var.security_group.egress.to_port
      protocol         = var.security_group.egress.protocol
      cidr_blocks      = var.security_group.egress.cidr_blocks
      ipv6_cidr_blocks = var.security_group.egress.ipv6_cidr_blocks
    }

  }

  tags = merge({ "Name" = "${var.name}-sg" }, var.instance_tags, var.custom_tags)
}
################################################################################
# Key pair
################################################################################

resource "aws_key_pair" "this" {
  count      = var.create_new_key != null ? 1 : 0
  key_name   = var.create_new_key.key_name
  public_key = var.create_new_key.public_key
}


################################################################################
# IAM Role / Instance Profile
################################################################################

locals {
  iam_role_name = try(coalesce(var.iam_role_name, var.name), "")
}

data "aws_iam_policy_document" "assume_role_policy" {
  count = var.create_iam_instance_profile ? 1 : 0

  statement {
    sid     = "EC2AssumeRole"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role" "this" {
  count = var.create_iam_instance_profile ? 1 : 0

  name        = var.iam_role_use_name_prefix ? null : local.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${local.iam_role_name}-" : null
  path        = var.iam_role_path
  description = var.iam_role_description

  assume_role_policy    = data.aws_iam_policy_document.assume_role_policy[0].json
  permissions_boundary  = var.iam_role_permissions_boundary
  force_detach_policies = true

  tags = merge(var.custom_tags, var.iam_role_tags)
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each = { for k, v in var.iam_role_policies : k => v if var.create_iam_instance_profile }

  policy_arn = each.value
  role       = aws_iam_role.this[0].name
}

resource "aws_iam_instance_profile" "this" {
  count = var.create_iam_instance_profile ? 1 : 0

  role = aws_iam_role.this[0].name

  name        = var.iam_role_use_name_prefix ? null : local.iam_role_name
  name_prefix = var.iam_role_use_name_prefix ? "${local.iam_role_name}-" : null
  path        = var.iam_role_path

  tags = merge(var.custom_tags, var.iam_role_tags)

  lifecycle {
    create_before_destroy = true
  }
}