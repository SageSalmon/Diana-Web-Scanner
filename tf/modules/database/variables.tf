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

variable "private_subnet_ids" {
  description = "Private subnet IDs for RDS"
  type        = list(string)
}

variable "data_sg_id" {
  description = "Security group ID for data tier"
  type        = string
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "diana_admin"
  sensitive   = true
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}

variable "db_min_capacity" {
  description = "Aurora Serverless v2 minimum ACUs"
  type        = number
  default     = 0.5
}

variable "db_max_capacity" {
  description = "Aurora Serverless v2 maximum ACUs"
  type        = number
  default     = 4
}
