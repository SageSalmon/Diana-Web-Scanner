output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.diana.id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "scanner_sg_id" {
  description = "Security group ID for scanner containers"
  value       = aws_security_group.scanner.id
}

output "test_targets_sg_id" {
  description = "Security group ID for test target containers"
  value       = aws_security_group.test_targets.id
}

output "data_sg_id" {
  description = "Security group ID for data tier (RDS, ElastiCache)"
  value       = aws_security_group.data.id
}

output "alb_sg_id" {
  description = "Security group ID for the ALB"
  value       = aws_security_group.alb.id
}

output "bedrock_endpoint_sg_id" {
  description = "Security group ID for the Bedrock VPC endpoint"
  value       = aws_security_group.bedrock_endpoint.id
}
