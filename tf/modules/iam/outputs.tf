output "ecs_execution_role_arn" {
  description = "ECS task execution role ARN"
  value       = aws_iam_role.ecs_execution.arn
}

output "scanner_task_role_arn" {
  description = "Scanner task role ARN (Bedrock + S3 + CloudWatch)"
  value       = aws_iam_role.scanner_task.arn
}

output "test_target_task_role_arn" {
  description = "Test target task role ARN (no AWS API access)"
  value       = aws_iam_role.test_target_task.arn
}
