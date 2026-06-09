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

variable "reports_bucket_arn" {
  description = "ARN of the S3 reports bucket"
  type        = string
}

variable "log_group_arn" {
  description = "ARN of the CloudWatch log group"
  type        = string
}

variable "api_key_secret_arn" {
  description = "ARN of the Secrets Manager secret for the API key"
  type        = string
}
