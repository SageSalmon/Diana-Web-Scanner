variable "project" {
  description = "Project name prefix"
  type        = string
  default     = "diana"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for test target tasks"
  type        = list(string)
}

variable "cluster_arn" {
  description = "ECS cluster ARN"
  type        = string
}

variable "test_targets_sg_id" {
  description = "Security group ID for test targets (inbound from scanner only)"
  type        = string
}

variable "execution_role_arn" {
  description = "ECS task execution role ARN"
  type        = string
}

variable "test_target_task_role_arn" {
  description = "Test target task role ARN (no AWS API access)"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group name"
  type        = string
}

variable "enable_targets" {
  description = "Set to false to scale test targets to zero"
  type        = bool
  default     = true
}
