################################################################################
# Diana — Database Module
#
# RDS PostgreSQL for scan results, findings, and engagement records.
################################################################################

resource "aws_db_subnet_group" "diana" {
  name       = "${var.project}-db"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "${var.project}-db-subnet-group"
  }
}

resource "aws_rds_cluster" "diana" {
  cluster_identifier = "${var.project}-db"
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = "16.11"
  database_name      = "diana"
  master_username    = var.db_username
  master_password    = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.diana.name
  vpc_security_group_ids = [var.data_sg_id]

  storage_encrypted   = true
  deletion_protection = var.environment == "prod"
  skip_final_snapshot = var.environment == "dev"

  serverlessv2_scaling_configuration {
    min_capacity = var.db_min_capacity
    max_capacity = var.db_max_capacity
  }

  tags = {
    Name        = "${var.project}-db"
    Environment = var.environment
  }
}

resource "aws_rds_cluster_instance" "diana" {
  count              = var.environment == "prod" ? 2 : 1
  identifier         = "${var.project}-db-${count.index}"
  cluster_identifier = aws_rds_cluster.diana.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.diana.engine
  engine_version     = aws_rds_cluster.diana.engine_version

  tags = {
    Name        = "${var.project}-db-instance-${count.index}"
    Environment = var.environment
  }
}
