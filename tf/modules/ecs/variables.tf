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

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for ALB"
  type        = list(string)
}

variable "scanner_sg_id" {
  description = "Security group ID for scanner containers"
  type        = string
}

variable "alb_sg_id" {
  description = "Security group ID for ALB"
  type        = string
}

variable "execution_role_arn" {
  description = "ECS task execution role ARN"
  type        = string
}

variable "scanner_task_role_arn" {
  description = "Scanner task role ARN"
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS"
  type        = string
}

variable "scanner_cpu" {
  description = "Scanner task CPU units"
  type        = number
  default     = 1024
}

variable "scanner_memory" {
  description = "Scanner task memory (MiB)"
  type        = number
  default     = 2048
}

variable "scanner_desired_count" {
  description = "Desired number of scanner tasks"
  type        = number
  default     = 1
}

variable "scanner_max_count" {
  description = "Maximum number of scanner tasks for auto-scaling"
  type        = number
  default     = 4
}

variable "bedrock_model_id" {
  description = "Bedrock model ID for AI operations"
  type        = string
  default     = "anthropic.claude-sonnet-4-6"
}

# Data tier connection info
variable "db_endpoint" {
  type = string
}

variable "db_name" {
  type = string
}

variable "db_username" {
  type      = string
  sensitive = true
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "redis_endpoint" {
  type = string
}

variable "redis_port" {
  type    = number
  default = 6379
}

variable "reports_bucket_name" {
  type = string
}

variable "log_group_name" {
  type = string
}

variable "api_key_secret_arn" {
  description = "Secrets Manager ARN for API key injection"
  type        = string
}
