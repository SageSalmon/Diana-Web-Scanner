################################################################################
# Diana — IAM Module
#
# ECS task execution role + task role with Bedrock, S3, and CloudWatch access.
################################################################################

# --- ECS Task Execution Role (ECR pull, CloudWatch logs) --------------------

resource "aws_iam_role" "ecs_execution" {
  name = "${var.project}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = { Name = "${var.project}-ecs-execution" }
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Scanner Task Role (Bedrock, S3, CloudWatch) ---------------------------

resource "aws_iam_role" "scanner_task" {
  name = "${var.project}-scanner-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = { Name = "${var.project}-scanner-task" }
}

resource "aws_iam_role_policy" "bedrock_access" {
  name = "${var.project}-bedrock-access"
  role = aws_iam_role.scanner_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockInvoke"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ]
        Resource = "arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.claude-*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "s3_reports" {
  name = "${var.project}-s3-reports"
  role = aws_iam_role.scanner_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReportBucket"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.reports_bucket_arn,
          "${var.reports_bucket_arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_logs" {
  name = "${var.project}-cloudwatch-logs"
  role = aws_iam_role.scanner_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${var.log_group_arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "secrets_api_key" {
  name = "${var.project}-secrets-api-key"
  role = aws_iam_role.scanner_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadApiKeySecret"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = var.api_key_secret_arn
      }
    ]
  })
}

# Also allow ECS execution role to pull the secret for container injection
resource "aws_iam_role_policy" "execution_secrets" {
  name = "${var.project}-execution-secrets"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PullApiKeySecret"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = var.api_key_secret_arn
      }
    ]
  })
}

# --- Test Target Task Role (minimal - no AWS API access) --------------------

resource "aws_iam_role" "test_target_task" {
  name = "${var.project}-test-target-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = { Name = "${var.project}-test-target-task" }
}

# No policies attached — test targets get zero AWS API access
