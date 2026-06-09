################################################################################
# Diana — ECS Module
#
# Fargate cluster, ALB, and scanner service (API + workers).
################################################################################

# --- ECS Cluster -------------------------------------------------------------

resource "aws_ecs_cluster" "diana" {
  name = "${var.project}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.project}-cluster"
    Environment = var.environment
  }
}

# --- ECR Repository ----------------------------------------------------------

resource "aws_ecr_repository" "scanner" {
  name                 = "${var.project}-scanner"
  image_tag_mutability = "MUTABLE"
  force_delete         = var.environment == "dev"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project}-scanner-ecr"
  }
}

# --- ALB ---------------------------------------------------------------------

resource "aws_lb" "diana" {
  name               = "${var.project}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids

  tags = {
    Name        = "${var.project}-alb"
    Environment = var.environment
  }
}

resource "aws_lb_target_group" "scanner" {
  name        = "${var.project}-scanner-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = {
    Name = "${var.project}-scanner-tg"
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.diana.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.scanner.arn
  }
}

# --- Scanner Task Definition -------------------------------------------------

resource "aws_ecs_task_definition" "scanner" {
  family                   = "${var.project}-scanner"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.scanner_cpu
  memory                   = var.scanner_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.scanner_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "diana-api"
      image     = "${aws_ecr_repository.scanner.repository_url}:latest"
      essential = true
      command   = ["serve", "--port", "8000"]

      portMappings = [{
        containerPort = 8000
        protocol      = "tcp"
      }]

      environment = [
        { name = "AWS_REGION", value = var.aws_region },
        { name = "DATABASE_URL", value = "postgresql://${var.db_username}:${var.db_password}@${var.db_endpoint}:5432/${var.db_name}" },
        { name = "REDIS_URL", value = "rediss://${var.redis_endpoint}:${var.redis_port}" },
        { name = "S3_REPORTS_BUCKET", value = var.reports_bucket_name },
        { name = "BEDROCK_MODEL_ID", value = var.bedrock_model_id },
      ]

      secrets = [
        {
          name      = "DIANA_API_KEY"
          valueFrom = var.api_key_secret_arn
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "scanner"
        }
      }

      # Note: L4 iptables enforcement not available on Fargate.
      # Network-level scope enforcement handled by security groups instead.
}
  ])

  tags = {
    Name        = "${var.project}-scanner-task"
    Environment = var.environment
  }
}

# --- Scanner Service ---------------------------------------------------------

resource "aws_ecs_service" "scanner" {
  name            = "${var.project}-scanner"
  cluster         = aws_ecs_cluster.diana.id
  task_definition = aws_ecs_task_definition.scanner.arn
  desired_count   = var.scanner_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.scanner_sg_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.scanner.arn
    container_name   = "diana-api"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.https]

  tags = {
    Name        = "${var.project}-scanner-service"
    Environment = var.environment
  }
}

# --- Auto Scaling ------------------------------------------------------------

resource "aws_appautoscaling_target" "scanner" {
  max_capacity       = var.scanner_max_count
  min_capacity       = var.scanner_desired_count
  resource_id        = "service/${aws_ecs_cluster.diana.name}/${aws_ecs_service.scanner.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "scanner_cpu" {
  name               = "${var.project}-scanner-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.scanner.resource_id
  scalable_dimension = aws_appautoscaling_target.scanner.scalable_dimension
  service_namespace  = aws_appautoscaling_target.scanner.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 70.0

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
