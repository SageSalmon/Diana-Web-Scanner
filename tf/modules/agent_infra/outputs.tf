output "artifacts_bucket_name" {
  description = "S3 bucket name for agent artifacts"
  value       = aws_s3_bucket.artifacts.bucket
}

output "artifacts_bucket_arn" {
  description = "S3 bucket ARN for agent artifacts"
  value       = aws_s3_bucket.artifacts.arn
}

output "codebuild_project_name" {
  description = "CodeBuild project name for building Diana images"
  value       = aws_codebuild_project.diana_build.name
}

output "validation_task_definition_arn" {
  description = "ARN of the validation agent ECS task definition"
  value       = aws_ecs_task_definition.validation.arn
}

output "test_runner_task_definition_arn" {
  description = "ARN of the test runner agent ECS task definition"
  value       = aws_ecs_task_definition.test_runner.arn
}

output "benchmark_task_definition_arn" {
  description = "ARN of the benchmark agent ECS task definition"
  value       = aws_ecs_task_definition.benchmark.arn
}

output "agent_task_role_arn" {
  description = "IAM role ARN for agent ECS tasks"
  value       = aws_iam_role.agent_task.arn
}
