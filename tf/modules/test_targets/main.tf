################################################################################
# Diana — Test Targets Module
#
# ECS Fargate services for Juice Shop, DVWA, and WebGoat.
# Locked down in a security group that ONLY allows inbound from the scanner SG.
# No public access. No other internal access. Zero AWS API permissions.
################################################################################

# --- Service Discovery (so scanner can resolve targets by name) --------------

resource "aws_service_discovery_private_dns_namespace" "targets" {
  name = "${var.project}.internal"
  vpc  = var.vpc_id

  tags = {
    Name = "${var.project}-targets-dns"
  }
}

# --- Juice Shop --------------------------------------------------------------

resource "aws_service_discovery_service" "juice_shop" {
  name = "juice-shop"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.targets.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_ecs_task_definition" "juice_shop" {
  family                   = "${var.project}-juice-shop"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.test_target_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "juice-shop"
      image     = "bkimminich/juice-shop:latest"
      essential = true

      portMappings = [{
        containerPort = 3000
        protocol      = "tcp"
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "juice-shop"
        }
      }
    }
  ])

  tags = { Name = "${var.project}-juice-shop" }
}

resource "aws_ecs_service" "juice_shop" {
  name            = "${var.project}-juice-shop"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.juice_shop.arn
  desired_count   = var.enable_targets ? 1 : 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.test_targets_sg_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.juice_shop.arn
  }

  tags = { Name = "${var.project}-juice-shop-service" }
}

# --- DVWA --------------------------------------------------------------------

resource "aws_service_discovery_service" "dvwa" {
  name = "dvwa"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.targets.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_ecs_task_definition" "dvwa" {
  family                   = "${var.project}-dvwa"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.test_target_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "dvwa"
      image     = "vulnerables/web-dvwa:latest"
      essential = true

      portMappings = [{
        containerPort = 80
        protocol      = "tcp"
      }]

      environment = [
        { name = "MYSQL_DATABASE", value = "dvwa" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dvwa"
        }
      }
    }
  ])

  tags = { Name = "${var.project}-dvwa" }
}

resource "aws_ecs_service" "dvwa" {
  name            = "${var.project}-dvwa"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.dvwa.arn
  desired_count   = var.enable_targets ? 1 : 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.test_targets_sg_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.dvwa.arn
  }

  tags = { Name = "${var.project}-dvwa-service" }
}

# --- WebGoat -----------------------------------------------------------------

resource "aws_service_discovery_service" "webgoat" {
  name = "webgoat"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.targets.id

    dns_records {
      ttl  = 10
      type = "A"
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_ecs_task_definition" "webgoat" {
  family                   = "${var.project}-webgoat"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.test_target_task_role_arn

  container_definitions = jsonencode([
    {
      name      = "webgoat"
      image     = "webgoat/webgoat:latest"
      essential = true

      portMappings = [{
        containerPort = 8080
        protocol      = "tcp"
      }]

      environment = [
        { name = "WEBGOAT_PORT", value = "8080" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "webgoat"
        }
      }
    }
  ])

  tags = { Name = "${var.project}-webgoat" }
}

resource "aws_ecs_service" "webgoat" {
  name            = "${var.project}-webgoat"
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.webgoat.arn
  desired_count   = var.enable_targets ? 1 : 0
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.test_targets_sg_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.webgoat.arn
  }

  tags = { Name = "${var.project}-webgoat-service" }
}
