variable "project" {
  description = "Project name prefix"
  type        = string
  default     = "diana"
}

variable "environment" {
  description = "Environment (dev, prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# --- References to existing infrastructure ---

variable "ecr_repository_url" {
  description = "ECR repository URL for Diana scanner images"
  type        = string
}

variable "execution_role_arn" {
  description = "ECS task execution role ARN (ECR pull, CloudWatch)"
  type        = string
}

variable "cluster_arn" {
  description = "ECS cluster ARN to run agent tasks on"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for agent tasks"
  type        = list(string)
}

variable "scanner_sg_id" {
  description = "Security group for scanner tasks (allows access to test targets)"
  type        = string
}

variable "log_group_name" {
  description = "CloudWatch log group name"
  type        = string
}

variable "log_group_arn" {
  description = "CloudWatch log group ARN"
  type        = string
}

# --- Database (for validation + benchmark scans) ---

variable "db_endpoint" {
  description = "RDS cluster endpoint"
  type        = string
}

variable "db_name" {
  description = "RDS database name"
  type        = string
  default     = "diana"
}

variable "db_username" {
  description = "RDS username"
  type        = string
  sensitive   = true
}

variable "db_password" {
  description = "RDS password"
  type        = string
  sensitive   = true
}

# --- CodeBuild ---

variable "github_repo_url" {
  description = "GitHub repository URL for Diana source"
  type        = string
}
