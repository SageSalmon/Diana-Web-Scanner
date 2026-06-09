variable "project" {
  description = "Project name prefix"
  type        = string
  default     = "diana"
}

variable "domain_name" {
  description = "FQDN for the Diana API (e.g. diana.example.com)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID"
  type        = string
}

variable "alb_dns_name" {
  description = "ALB DNS name for alias record"
  type        = string
}

variable "alb_zone_id" {
  description = "ALB hosted zone ID for alias record"
  type        = string
}
