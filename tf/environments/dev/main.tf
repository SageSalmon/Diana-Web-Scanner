################################################################################
# Diana — Dev Environment
#
# Wires all modules together for the development environment.
# Test targets enabled, single-AZ, minimal sizing.
################################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configured via: terraform init -backend-config=backend.hcl
  # See backend.hcl.example for the template
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "diana"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

# --- Networking --------------------------------------------------------------

module "networking" {
  source = "../../modules/networking"

  project             = var.project
  aws_region          = var.aws_region
  vpc_cidr            = var.vpc_cidr
  az_count            = 2
  allowed_cidr_blocks = var.allowed_cidr_blocks
}

# --- Storage (S3, ElastiCache, CloudWatch) -----------------------------------

module "storage" {
  source = "../../modules/storage"

  project            = var.project
  environment        = "dev"
  private_subnet_ids = module.networking.private_subnet_ids
  data_sg_id         = module.networking.data_sg_id
  redis_node_type    = "cache.t4g.micro"
  log_retention_days = 14
  api_key            = var.api_key
}

# --- Database ----------------------------------------------------------------

module "database" {
  source = "../../modules/database"

  project            = var.project
  environment        = "dev"
  private_subnet_ids = module.networking.private_subnet_ids
  data_sg_id         = module.networking.data_sg_id
  db_username        = var.db_username
  db_password        = var.db_password
  db_min_capacity    = 0.5
  db_max_capacity    = 2
}

# --- IAM ---------------------------------------------------------------------

module "iam" {
  source = "../../modules/iam"

  project            = var.project
  aws_region         = var.aws_region
  reports_bucket_arn = module.storage.reports_bucket_arn
  log_group_arn      = module.storage.log_group_arn
  api_key_secret_arn = module.storage.api_key_secret_arn
}

# --- ECS (Scanner) -----------------------------------------------------------

module "ecs" {
  source = "../../modules/ecs"

  project               = var.project
  environment           = "dev"
  aws_region            = var.aws_region
  vpc_id                = module.networking.vpc_id
  private_subnet_ids    = module.networking.private_subnet_ids
  public_subnet_ids     = module.networking.public_subnet_ids
  scanner_sg_id         = module.networking.scanner_sg_id
  alb_sg_id             = module.networking.alb_sg_id
  execution_role_arn    = module.iam.ecs_execution_role_arn
  scanner_task_role_arn = module.iam.scanner_task_role_arn
  certificate_arn       = module.dns.certificate_arn

  scanner_cpu           = 1024
  scanner_memory        = 2048
  scanner_desired_count = 1
  scanner_max_count     = 2
  bedrock_model_id      = var.bedrock_model_id

  db_endpoint         = module.database.cluster_endpoint
  db_name             = module.database.database_name
  db_username         = var.db_username
  db_password         = var.db_password
  redis_endpoint      = module.storage.redis_endpoint
  redis_port          = module.storage.redis_port
  reports_bucket_name = module.storage.reports_bucket_name
  log_group_name      = module.storage.log_group_name
  api_key_secret_arn  = module.storage.api_key_secret_arn
}

# --- DNS (ACM cert + Route 53 alias) -----------------------------------------

module "dns" {
  source = "../../modules/dns"

  project        = var.project
  domain_name    = var.domain_name
  hosted_zone_id = var.hosted_zone_id
  alb_dns_name   = module.ecs.alb_dns_name
  alb_zone_id    = module.ecs.alb_zone_id
}

# --- Agent Infrastructure (S3, CodeBuild, task definitions) ------------------

module "agent_infra" {
  source = "../../modules/agent_infra"

  project            = var.project
  environment        = "dev"
  aws_region         = var.aws_region
  ecr_repository_url = module.ecs.ecr_repository_url
  execution_role_arn = module.iam.ecs_execution_role_arn
  cluster_arn        = module.ecs.cluster_arn
  private_subnet_ids = module.networking.private_subnet_ids
  scanner_sg_id      = module.networking.scanner_sg_id
  log_group_name     = module.storage.log_group_name
  log_group_arn      = module.storage.log_group_arn
  db_endpoint        = module.database.cluster_endpoint
  db_name            = module.database.database_name
  db_username        = var.db_username
  db_password        = var.db_password
  github_repo_url    = var.github_repo_url
}

# --- Test Targets (Juice Shop, DVWA, WebGoat) --------------------------------

module "test_targets" {
  source = "../../modules/test_targets"

  project                   = var.project
  aws_region                = var.aws_region
  vpc_id                    = module.networking.vpc_id
  private_subnet_ids        = module.networking.private_subnet_ids
  cluster_arn               = module.ecs.cluster_arn
  test_targets_sg_id        = module.networking.test_targets_sg_id
  execution_role_arn        = module.iam.ecs_execution_role_arn
  test_target_task_role_arn = module.iam.test_target_task_role_arn
  log_group_name            = module.storage.log_group_name
  enable_targets            = var.enable_test_targets
}
