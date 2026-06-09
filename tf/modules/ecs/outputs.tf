output "cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.diana.name
}

output "cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.diana.arn
}

output "scanner_service_name" {
  description = "Scanner ECS service name"
  value       = aws_ecs_service.scanner.name
}

output "ecr_repository_url" {
  description = "ECR repository URL for scanner image"
  value       = aws_ecr_repository.scanner.repository_url
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.diana.dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID"
  value       = aws_lb.diana.zone_id
}
