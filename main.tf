### VPC Configuration
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${local.cluster_name}-vpc"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment == "dev" ? true : false
  enable_dns_hostnames = true
  enable_dns_support   = true

  # VPC Flow Logs for security
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

  # Kubernetes specific tags - Fixed tag format
  public_subnet_tags = {
    "kubernetes.io_role_elb"    = "1"
    "kubernetes.io_cluster_name" = local.cluster_name
  }

  private_subnet_tags = {
    "kubernetes.io_role_internal-elb" = "1"
    "kubernetes.io_cluster_name"      = local.cluster_name
  }

  tags = local.common_tags
}

### Security Groups

# Bastion Host Security Group
module "bastion_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${local.cluster_name}-bastion-sg"
  description = "Security group for bastion host - SSH access only"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "SSH from allowed IPs"
      cidr_blocks = join(",", var.allowed_ssh_cidr_blocks)
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      description = "Allow all outbound"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-bastion-sg" })
}

# Control Plane Security Group
module "control_plane_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${local.cluster_name}-control-plane-sg"
  description = "Security group for Kubernetes control plane"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 6443
      to_port     = 6443
      protocol    = "tcp"
      description = "Kubernetes API server"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
    {
      from_port   = 2379
      to_port     = 2380
      protocol    = "tcp"
      description = "etcd server client API"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks[0]
    },
    {
      from_port   = 10250
      to_port     = 10250
      protocol    = "tcp"
      description = "Kubelet API"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
    {
      from_port   = 10259
      to_port     = 10259
      protocol    = "tcp"
      description = "kube-scheduler"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks[0]
    },
    {
      from_port   = 10257
      to_port     = 10257
      protocol    = "tcp"
      description = "kube-controller-manager"
      cidr_blocks = module.vpc.private_subnets_cidr_blocks[0]
    }
  ]

  ingress_with_source_security_group_id = [
    {
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      description              = "SSH from bastion"
      source_security_group_id = module.bastion_sg.security_group_id
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      description = "Allow all outbound"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-control-plane-sg" })
}

# Worker Nodes Security Group
module "worker_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = "${local.cluster_name}-worker-sg"
  description = "Security group for Kubernetes worker nodes"
  vpc_id      = module.vpc.vpc_id

  ingress_with_cidr_blocks = [
    {
      from_port   = 10250
      to_port     = 10250
      protocol    = "tcp"
      description = "Kubelet API"
      cidr_blocks = module.vpc.vpc_cidr_block
    },
    {
      from_port   = 30000
      to_port     = 32767
      protocol    = "tcp"
      description = "NodePort Services"
      cidr_blocks = module.vpc.vpc_cidr_block
    }
  ]

  ingress_with_source_security_group_id = [
    {
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      description              = "SSH from bastion"
      source_security_group_id = module.bastion_sg.security_group_id
    },
    {
      from_port                = 0
      to_port                  = 0
      protocol                 = "-1"
      description              = "All traffic from control plane"
      source_security_group_id = module.control_plane_sg.security_group_id
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      description = "Allow all outbound"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-worker-sg" })
}

### IAM Roles and Policies

# Control Plane IAM Role
module "control_plane_iam_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"

  trusted_role_services   = ["ec2.amazonaws.com"]
  create_role             = true
  create_instance_profile = true
  role_name               = "${local.cluster_name}-control-plane-role"
  role_requires_mfa       = false

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  ]

  tags = local.common_tags
}

# Worker Node IAM Role with ECR Access
module "worker_iam_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"

  trusted_role_services   = ["ec2.amazonaws.com"]
  create_role             = true
  create_instance_profile = true
  role_name               = "${local.cluster_name}-worker-role"
  role_requires_mfa       = false

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    aws_iam_policy.worker_policy.arn
  ]

  tags = local.common_tags
}

# Custom Worker Policy
resource "aws_iam_policy" "worker_policy" {
  name        = "${local.cluster_name}-worker-policy"
  description = "Custom policy for K8s worker nodes"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVolumes",
          "ec2:DescribeVpcs",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyVolume",
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:RevokeSecurityGroupIngress",
          "elasticloadbalancing:*",
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

# Bastion Host IAM Role
module "bastion_iam_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "~> 5.0"

  trusted_role_services   = ["ec2.amazonaws.com"]
  create_role             = true
  create_instance_profile = true
  role_name               = "${local.cluster_name}-bastion-role"
  role_requires_mfa       = false

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ]

  tags = local.common_tags
}

### EC2 Instances

# Bastion Host
module "bastion_host" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 5.0"

  name = "${local.cluster_name}-bastion"

  instance_type               = var.bastion_instance_type
  ami                         = var.ami_id
  key_name                    = var.key_name
  monitoring                  = true
  vpc_security_group_ids      = [module.bastion_sg.security_group_id]
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  iam_instance_profile        = module.bastion_iam_role.iam_instance_profile_name

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      volume_size = 20
    }
  ]

  tags = merge(local.common_tags, { Name = "${local.cluster_name}-bastion" })
}

# Control Plane Instances
module "control_plane" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 5.0"

  for_each = toset(["master-1", "master-2", "master-3"])

  name = "${local.cluster_name}-${each.key}"

  instance_type          = var.control_plane_instance_type
  ami                    = var.ami_id
  key_name               = var.key_name
  monitoring             = true
  vpc_security_group_ids = [module.control_plane_sg.security_group_id, module.worker_sg.security_group_id]
  subnet_id              = element(module.vpc.private_subnets, index(tolist(toset(["master-1", "master-2", "master-3"])), each.key))
  iam_instance_profile   = module.control_plane_iam_role.iam_instance_profile_name

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      volume_size = 50
    }
  ]

  tags = merge(local.common_tags, {
    Name                         = "${local.cluster_name}-${each.key}"
    "kubernetes.io_cluster_name" = local.cluster_name
    Role                         = "control-plane"
  })
}

### Worker Nodes ASG - Mixed (Spot & On-Demand)
module "worker_asg_mixed" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 7.0"

  name = "${local.cluster_name}-worker-mixed"

  min_size                  = var.worker_mixed_min_size
  max_size                  = var.worker_mixed_max_size
  desired_capacity          = var.worker_mixed_desired_capacity
  wait_for_capacity_timeout = 0
  health_check_type         = "EC2"
  health_check_grace_period = 300
  vpc_zone_identifier       = module.vpc.private_subnets

  # Launch template
  launch_template_name        = "${local.cluster_name}-worker-mixed"
  launch_template_description = "Launch template for mixed pricing K8s worker nodes"
  update_default_version      = true

  image_id      = var.ami_id
  instance_type = var.worker_instance_type
  key_name      = var.key_name

  ebs_optimized     = true
  enable_monitoring = true

  # IAM
  create_iam_instance_profile = false
  iam_instance_profile_arn    = module.worker_iam_role.iam_instance_profile_arn

  # Security
  security_groups = [module.worker_sg.security_group_id]

  # Mixed instances policy
  use_mixed_instances_policy = true
  mixed_instances_policy = {
    instances_distribution = {
      on_demand_base_capacity                  = var.worker_ondemand_base_capacity
      on_demand_percentage_above_base_capacity = var.worker_ondemand_percentage_above_base
      spot_allocation_strategy                 = "capacity-optimized"
      spot_max_price                           = var.worker_spot_max_price != "" ? var.worker_spot_max_price : null
    }

    override = [
      {
        instance_type     = var.worker_instance_type
        weighted_capacity = "1"
      },
      {
        instance_type     = var.worker_instance_type_alternative
        weighted_capacity = "1"
      }
    ]
  }

  block_device_mappings = [
    {
      device_name = "/dev/xvda"
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 100
        volume_type           = "gp3"
        iops                  = 3000
        throughput            = 125
      }
    }
  ]

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = merge(local.common_tags, {
    Name                         = "${local.cluster_name}-worker-mixed"
    "kubernetes.io_cluster_name" = local.cluster_name
    Role                         = "worker"
    PricingModel                 = "mixed"
  })
}

### Worker Nodes ASG - On-Demand Only
module "worker_asg_ondemand" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 7.0"

  name = "${local.cluster_name}-worker-ondemand"

  min_size                  = var.worker_ondemand_min_size
  max_size                  = var.worker_ondemand_max_size
  desired_capacity          = var.worker_ondemand_desired_capacity
  wait_for_capacity_timeout = 0
  health_check_type         = "EC2"
  health_check_grace_period = 300
  vpc_zone_identifier       = module.vpc.private_subnets

  # Launch template
  launch_template_name        = "${local.cluster_name}-worker-ondemand"
  launch_template_description = "Launch template for on-demand K8s worker nodes"
  update_default_version      = true

  image_id      = var.ami_id
  instance_type = var.worker_instance_type
  key_name      = var.key_name

  ebs_optimized     = true
  enable_monitoring = true

  # IAM
  create_iam_instance_profile = false
  iam_instance_profile_arn    = module.worker_iam_role.iam_instance_profile_arn

  # Security
  security_groups = [module.worker_sg.security_group_id]

  block_device_mappings = [
    {
      device_name = "/dev/xvda"
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 100
        volume_type           = "gp3"
        iops                  = 3000
        throughput            = 125
      }
    }
  ]

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = merge(local.common_tags, {
    Name                         = "${local.cluster_name}-worker-ondemand"
    "kubernetes.io_cluster_name" = local.cluster_name
    Role                         = "worker"
    PricingModel                 = "on-demand"
  })
}

### Worker Nodes ASG - Spot Only
module "worker_asg_spot" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 7.0"

  name = "${local.cluster_name}-worker-spot"

  min_size                  = var.worker_spot_min_size
  max_size                  = var.worker_spot_max_size
  desired_capacity          = var.worker_spot_desired_capacity
  wait_for_capacity_timeout = 0
  health_check_type         = "EC2"
  health_check_grace_period = 300
  vpc_zone_identifier       = module.vpc.private_subnets

  # Launch template
  launch_template_name        = "${local.cluster_name}-worker-spot"
  launch_template_description = "Launch template for spot K8s worker nodes"
  update_default_version      = true

  image_id      = var.ami_id
  instance_type = var.worker_instance_type
  key_name      = var.key_name

  ebs_optimized     = true
  enable_monitoring = true

  # IAM
  create_iam_instance_profile = false
  iam_instance_profile_arn    = module.worker_iam_role.iam_instance_profile_arn

  # Security
  security_groups = [module.worker_sg.security_group_id]

  # Spot configuration
  instance_market_options = {
    market_type = "spot"
    spot_options = {
      max_price                      = var.worker_spot_max_price != "" ? var.worker_spot_max_price : null
      spot_instance_type             = "one-time"
      instance_interruption_behavior = "terminate"
    }
  }

  block_device_mappings = [
    {
      device_name = "/dev/xvda"
      ebs = {
        delete_on_termination = true
        encrypted             = true
        volume_size           = 100
        volume_type           = "gp3"
        iops                  = 3000
        throughput            = 125
      }
    }
  ]

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = merge(local.common_tags, {
    Name                         = "${local.cluster_name}-worker-spot"
    "kubernetes.io_cluster_name" = local.cluster_name
    Role                         = "worker"
    PricingModel                 = "spot"
  })
}
