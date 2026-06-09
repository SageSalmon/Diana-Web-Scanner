################################################################################
# Diana — Storage Module
#
# S3 bucket for scan reports and ElastiCache Redis for session caching.
################################################################################

# --- S3 Reports Bucket -------------------------------------------------------

resource "aws_s3_bucket" "reports" {
  bucket_prefix = "${var.project}-reports-"
  force_destroy = var.environment == "dev"

  tags = {
    Name        = "${var.project}-reports"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }
  }
}

# --- ElastiCache Redis -------------------------------------------------------

resource "aws_elasticache_subnet_group" "diana" {
  name       = "${var.project}-redis"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${var.project}-redis-subnet-group"
  }
}

resource "aws_elasticache_replication_group" "diana" {
  replication_group_id = "${var.project}-redis"
  description          = "Diana session cache and rate limiter"
  node_type            = var.redis_node_type
  num_cache_clusters   = var.environment == "prod" ? 2 : 1
  port                 = 6379
  engine_version       = "7.1"

  subnet_group_name  = aws_elasticache_subnet_group.diana.name
  security_group_ids = [var.data_sg_id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  automatic_failover_enabled = var.environment == "prod"

  tags = {
    Name        = "${var.project}-redis"
    Environment = var.environment
  }
}

# --- Secrets Manager (API Key) ------------------------------------------------

resource "aws_secretsmanager_secret" "api_key" {
  name        = "${var.project}/api-key"
  description = "Diana API authentication key"

  tags = {
    Name        = "${var.project}-api-key"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id     = aws_secretsmanager_secret.api_key.id
  secret_string = var.api_key
}

# --- CloudWatch Log Group ----------------------------------------------------

resource "aws_cloudwatch_log_group" "diana" {
  name              = "/ecs/${var.project}"
  retention_in_days = var.log_retention_days

  tags = {
    Name        = "${var.project}-logs"
    Environment = var.environment
  }
}
