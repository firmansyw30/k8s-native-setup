variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "k8s-cluster"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

variable "private_subnet_cidrs" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "allowed_ssh_cidr_blocks" {
  description = "CIDR blocks allowed to SSH to bastion"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Change this to your IP
}

variable "ami_id" {
  description = "AMI ID for instances (Ubuntu 22.04 LTS recommended)"
  type        = string
}

variable "key_name" {
  description = "EC2 Key Pair name"
  type        = string
}

variable "bastion_instance_type" {
  description = "Bastion host instance type"
  type        = string
  default     = "t3.micro"
}

variable "control_plane_instance_type" {
  description = "Control plane instance type"
  type        = string
  default     = "t3.medium"
}

variable "worker_instance_type" {
  description = "Worker node instance type"
  type        = string
  default     = "t3.medium"
}

variable "worker_ondemand_min_size" {
  description = "Minimum on-demand worker nodes"
  type        = number
  default     = 1
}

variable "worker_ondemand_max_size" {
  description = "Maximum on-demand worker nodes"
  type        = number
  default     = 3
}

variable "worker_ondemand_desired_capacity" {
  description = "Desired on-demand worker nodes"
  type        = number
  default     = 2
}

variable "worker_spot_min_size" {
  description = "Minimum spot worker nodes"
  type        = number
  default     = 0
}

variable "worker_spot_max_size" {
  description = "Maximum spot worker nodes"
  type        = number
  default     = 5
}

variable "worker_spot_desired_capacity" {
  description = "Desired spot worker nodes"
  type        = number
  default     = 2
}

variable "worker_spot_max_price" {
  description = "Maximum spot price (leave empty for on-demand price)"
  type        = string
  default     = ""
}

# Mixed Pricing Worker Configuration
variable "worker_mixed_min_size" {
  description = "Minimum mixed pricing worker nodes"
  type        = number
  default     = 2
}

variable "worker_mixed_max_size" {
  description = "Maximum mixed pricing worker nodes"
  type        = number
  default     = 10
}

variable "worker_mixed_desired_capacity" {
  description = "Desired mixed pricing worker nodes"
  type        = number
  default     = 4
}

variable "worker_ondemand_base_capacity" {
  description = "Minimum on-demand instances (base capacity)"
  type        = number
  default     = 1
}

variable "worker_ondemand_percentage_above_base" {
  description = "Percentage of on-demand instances above base capacity (0-100)"
  type        = number
  default     = 30
}

variable "worker_instance_type_alternative" {
  description = "Alternative worker node instance type for mixed policy"
  type        = string
  default     = "t3.large"
}