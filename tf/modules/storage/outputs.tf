output "reports_bucket_arn" {
  description = "S3 reports bucket ARN"
  value       = aws_s3_bucket.reports.arn
}

output "reports_bucket_name" {
  description = "S3 reports bucket name"
  value       = aws_s3_bucket.reports.id
}

output "redis_endpoint" {
  description = "ElastiCache Redis primary endpoint"
  value       = aws_elasticache_replication_group.diana.primary_endpoint_address
}

output "redis_port" {
  description = "ElastiCache Redis port"
  value       = aws_elasticache_replication_group.diana.port
}

output "api_key_secret_arn" {
  description = "Secrets Manager ARN for API key"
  value       = aws_secretsmanager_secret.api_key.arn
}

output "log_group_arn" {
  description = "CloudWatch log group ARN"
  value       = aws_cloudwatch_log_group.diana.arn
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.diana.name
}
