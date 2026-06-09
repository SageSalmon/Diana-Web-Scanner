################################################################################
# Diana — Agent Infrastructure Module
#
# S3 artifacts bucket, CodeBuild project, and ECS task definitions for the
# agent team (validation, test runner, benchmark).
################################################################################

# --- S3 Artifacts Bucket -----------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "${var.project}-agent-artifacts-"
  force_destroy = var.environment == "dev"

  tags = {
    Name        = "${var.project}-agent-artifacts"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }
}

# --- CodeBuild — Build Diana Image from Branch ------------------------------

resource "aws_codebuild_project" "diana_build" {
  name         = "${var.project}-agent-build"
  description  = "Build Diana scanner image from a git branch for agent tasks"
  service_role = aws_iam_role.codebuild.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true

    environment_variable {
      name  = "ECR_REPO_URL"
      value = var.ecr_repository_url
    }

    environment_variable {
      name  = "AWS_DEFAULT_REGION"
      value = var.aws_region
    }
  }

  source {
    type            = "GITHUB"
    location        = var.github_repo_url
    git_clone_depth = 1
    buildspec       = <<-BUILDSPEC
      version: 0.2
      phases:
        pre_build:
          commands:
            - echo Logging in to ECR...
            - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $ECR_REPO_URL
            - BRANCH_TAG=$(echo $BRANCH_REF | sed 's/[^a-zA-Z0-9_.-]/-/g')
            - GIT_SHA=$(git rev-parse --short HEAD)
        build:
          commands:
            - echo "Building Diana image for branch $BRANCH_REF ($GIT_SHA)..."
            - docker build --build-arg GIT_SHA=$GIT_SHA --build-arg IMAGE_TAG=$BRANCH_TAG -t $ECR_REPO_URL:$BRANCH_TAG -t $ECR_REPO_URL:agent-latest .
        post_build:
          commands:
            - echo Pushing image...
            - docker push $ECR_REPO_URL:$BRANCH_TAG
            - docker push $ECR_REPO_URL:agent-latest
            - echo "{\"image\":\"$ECR_REPO_URL:$BRANCH_TAG\"}" > /tmp/build-output.json
    BUILDSPEC
  }

  logs_config {
    cloudwatch_logs {
      group_name  = var.log_group_name
      stream_name = "agent-build"
    }
  }

  tags = {
    Name        = "${var.project}-agent-build"
    Environment = var.environment
  }
}

# --- CodeBuild IAM Role -----------------------------------------------------

resource "aws_iam_role" "codebuild" {
  name = "${var.project}-agent-codebuild"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "codebuild.amazonaws.com"
      }
    }]
  })

  tags = { Name = "${var.project}-agent-codebuild" }
}

resource "aws_iam_role_policy" "codebuild" {
  name = "${var.project}-agent-codebuild"
  role = aws_iam_role.codebuild.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ECRPushPull"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# --- Agent Task Role (Bedrock + S3 artifacts + CloudWatch) -------------------

resource "aws_iam_role" "agent_task" {
  name = "${var.project}-agent-task"

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

  tags = { Name = "${var.project}-agent-task" }
}

resource "aws_iam_role_policy" "agent_bedrock" {
  name = "${var.project}-agent-bedrock"
  role = aws_iam_role.agent_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "BedrockInvoke"
      Effect = "Allow"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ]
      Resource = "arn:aws:bedrock:${var.aws_region}::foundation-model/*"
    }]
  })
}

resource "aws_iam_role_policy" "agent_s3_artifacts" {
  name = "${var.project}-agent-s3-artifacts"
  role = aws_iam_role.agent_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "S3ArtifactsBucket"
      Effect = "Allow"
      Action = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        aws_s3_bucket.artifacts.arn,
        "${aws_s3_bucket.artifacts.arn}/*"
      ]
    }]
  })
}

resource "aws_iam_role_policy" "agent_cloudwatch" {
  name = "${var.project}-agent-cloudwatch"
  role = aws_iam_role.agent_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "CloudWatchLogs"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${var.log_group_arn}:*"
    }]
  })
}

# --- Validation Task Definition (Diana + Juice Shop sidecar) ----------------

resource "aws_ecs_task_definition" "validation" {
  family                   = "${var.project}-agent-validation"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 2048
  memory                   = 4096
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.agent_task.arn

  container_definitions = jsonencode([
    {
      name      = "diana-scanner"
      image     = "${var.ecr_repository_url}:agent-latest"
      essential = true
      entryPoint = ["/bin/bash", "/app/scripts/entrypoint-validation.sh"]
      command    = []

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DIANA_LLM_PROVIDER", value = "bedrock" },
        { name = "DIANA_AI_ENABLED", value = "true" },
        { name = "S3_ARTIFACTS_BUCKET", value = aws_s3_bucket.artifacts.bucket },
        { name = "TARGET_URL", value = "http://localhost:3000" },
        { name = "DATABASE_URL", value = "postgresql://${var.db_username}:${var.db_password}@${var.db_endpoint}:5432/${var.db_name}" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent-validation"
        }
      }
    },
    {
      name      = "juice-shop"
      image     = "bkimminich/juice-shop:latest"
      essential = false

      portMappings = [{
        containerPort = 3000
        protocol      = "tcp"
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent-validation-juiceshop"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project}-agent-validation"
    Environment = var.environment
  }
}

# --- Test Runner Task Definition (Diana only, no target) ---------------------

resource "aws_ecs_task_definition" "test_runner" {
  family                   = "${var.project}-agent-test"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.agent_task.arn

  container_definitions = jsonencode([
    {
      name      = "diana-test"
      image     = "${var.ecr_repository_url}:agent-latest"
      essential = true
      entryPoint = ["/bin/bash", "/app/scripts/entrypoint-test.sh"]
      command    = []

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "S3_ARTIFACTS_BUCKET", value = aws_s3_bucket.artifacts.bucket },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent-test"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project}-agent-test"
    Environment = var.environment
  }
}

# --- Benchmark Task Definition (Diana + Juice Shop sidecar) -----------------

resource "aws_ecs_task_definition" "benchmark" {
  family                   = "${var.project}-agent-benchmark"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 2048
  memory                   = 4096
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = aws_iam_role.agent_task.arn

  container_definitions = jsonencode([
    {
      name      = "diana-scanner"
      image     = "${var.ecr_repository_url}:agent-latest"
      essential = true
      entryPoint = ["/bin/bash", "/app/scripts/entrypoint-benchmark.sh"]
      command    = []

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DIANA_LLM_PROVIDER", value = "bedrock" },
        { name = "DIANA_AI_ENABLED", value = "true" },
        { name = "S3_ARTIFACTS_BUCKET", value = aws_s3_bucket.artifacts.bucket },
        { name = "TARGET_URL", value = "http://localhost:3000" },
        { name = "DATABASE_URL", value = "postgresql://${var.db_username}:${var.db_password}@${var.db_endpoint}:5432/${var.db_name}" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent-benchmark"
        }
      }
    },
    {
      name      = "juice-shop"
      image     = "bkimminich/juice-shop:latest"
      essential = false

      portMappings = [{
        containerPort = 3000
        protocol      = "tcp"
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "agent-benchmark-juiceshop"
        }
      }
    }
  ])

  tags = {
    Name        = "${var.project}-agent-benchmark"
    Environment = var.environment
  }
}
