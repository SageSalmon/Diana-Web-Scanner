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

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the ALB API"
  type        = list(string)
  default     = []
}

variable "domain_name" {
  description = "FQDN for Diana API (e.g. diana.example.com)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for your domain"
  type        = string
}

variable "db_username" {
  description = "RDS master username"
  type        = string
  default     = "diana_admin"
  sensitive   = true
}

variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}

variable "bedrock_model_id" {
  description = "Bedrock model ID"
  type        = string
  default     = "anthropic.claude-sonnet-4-6"
}

variable "api_key" {
  description = "API key for Diana API authentication"
  type        = string
  sensitive   = true
}

variable "github_repo_url" {
  description = "GitHub repository URL for Diana source (used by CodeBuild)"
  type        = string
}

variable "enable_test_targets" {
  description = "Deploy test targets (Juice Shop, DVWA, WebGoat)"
  type        = bool
  default     = true
}
