output "diana_url" {
  description = "Diana API URL"
  value       = "https://${module.dns.fqdn}"
}

output "alb_dns_name" {
  description = "ALB DNS name for Diana API"
  value       = module.ecs.alb_dns_name
}

output "ecr_repository_url" {
  description = "ECR repository URL — push scanner image here"
  value       = module.ecs.ecr_repository_url
}

output "juice_shop_dns" {
  description = "Juice Shop internal DNS"
  value       = module.test_targets.juice_shop_dns
}

output "dvwa_dns" {
  description = "DVWA internal DNS"
  value       = module.test_targets.dvwa_dns
}

output "webgoat_dns" {
  description = "WebGoat internal DNS"
  value       = module.test_targets.webgoat_dns
}

output "agent_artifacts_bucket" {
  description = "S3 bucket for agent team artifacts"
  value       = module.agent_infra.artifacts_bucket_name
}

output "agent_codebuild_project" {
  description = "CodeBuild project for building Diana agent images"
  value       = module.agent_infra.codebuild_project_name
}

output "cluster_arn" {
  description = "ECS cluster ARN"
  value       = module.ecs.cluster_arn
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = join(",", module.networking.private_subnet_ids)
}

output "scanner_sg_id" {
  description = "Scanner security group ID"
  value       = module.networking.scanner_sg_id
}

output "db_endpoint" {
  description = "RDS cluster endpoint"
  value       = module.database.cluster_endpoint
}

output "redis_endpoint" {
  description = "ElastiCache Redis endpoint"
  value       = module.storage.redis_endpoint
}

output "reports_bucket" {
  description = "S3 reports bucket name"
  value       = module.storage.reports_bucket_name
}
