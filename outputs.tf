output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

output "bastion_public_ip" {
  description = "Bastion host public IP"
  value       = module.bastion_host.public_ip
}

output "bastion_instance_id" {
  description = "Bastion host instance ID"
  value       = module.bastion_host.id
}

output "control_plane_private_ips" {
  description = "Control plane private IPs"
  value       = { for k, v in module.control_plane : k => v.private_ip }
}

output "control_plane_instance_ids" {
  description = "Control plane instance IDs"
  value       = { for k, v in module.control_plane : k => v.id }
}

output "worker_ondemand_asg_name" {
  description = "On-demand worker ASG name"
  value       = module.worker_asg_ondemand.autoscaling_group_name
}

output "worker_spot_asg_name" {
  description = "Spot worker ASG name"
  value       = module.worker_asg_spot.autoscaling_group_name
}

output "worker_iam_role_arn" {
  description = "Worker node IAM role ARN"
  value       = module.worker_iam_role.iam_role_arn
}

output "bastion_sg_id" {
  description = "Bastion security group ID"
  value       = module.bastion_sg.security_group_id
}

output "control_plane_sg_id" {
  description = "Control plane security group ID"
  value       = module.control_plane_sg.security_group_id
}

output "worker_sg_id" {
  description = "Worker security group ID"
  value       = module.worker_sg.security_group_id
}