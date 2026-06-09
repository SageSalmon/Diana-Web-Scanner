################################################################################
# Diana - Networking Module
#
# VPC, subnets, and security groups. The security groups enforce the
# engagement-scoped network boundary:
#   - Scanner SG: egress to test targets + Bedrock only
#   - Test Targets SG: inbound ONLY from Scanner SG
#   - Data SG: inbound ONLY from Scanner SG
################################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "diana" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project}-vpc"
  }
}

# --- Subnets -----------------------------------------------------------------

resource "aws_subnet" "private" {
  count             = var.az_count
  vpc_id            = aws_vpc.diana.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.project}-private-${count.index}"
  }
}

resource "aws_subnet" "public" {
  count                   = var.az_count
  vpc_id                  = aws_vpc.diana.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 100)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project}-public-${count.index}"
  }
}

# --- Internet & NAT Gateways ------------------------------------------------

resource "aws_internet_gateway" "diana" {
  vpc_id = aws_vpc.diana.id

  tags = {
    Name = "${var.project}-igw"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project}-nat-eip"
  }
}

resource "aws_nat_gateway" "diana" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project}-nat"
  }

  depends_on = [aws_internet_gateway.diana]
}

# --- Route Tables ------------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.diana.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.diana.id
  }

  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.diana.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.diana.id
  }

  tags = {
    Name = "${var.project}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = var.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- VPC Endpoint for Bedrock (avoids NAT costs for AI traffic) --------------

resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = aws_vpc.diana.id
  service_name        = "com.amazonaws.${var.aws_region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project}-bedrock-vpce"
  }
}

# --- Security Groups (shells - no inline rules to avoid cycles) --------------

resource "aws_security_group" "scanner" {
  name_prefix = "${var.project}-scanner-"
  description = "Diana scanner - egress restricted to in-scope targets"
  vpc_id      = aws_vpc.diana.id
  tags        = { Name = "${var.project}-scanner-sg" }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "test_targets" {
  name_prefix = "${var.project}-test-targets-"
  description = "Diana test targets - inbound ONLY from scanner SG"
  vpc_id      = aws_vpc.diana.id
  tags        = { Name = "${var.project}-test-targets-sg" }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "data" {
  name_prefix = "${var.project}-data-"
  description = "Diana data tier - inbound ONLY from scanner SG"
  vpc_id      = aws_vpc.diana.id
  tags        = { Name = "${var.project}-data-sg" }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.project}-alb-"
  description = "Diana ALB - HTTPS ingress"
  vpc_id      = aws_vpc.diana.id
  tags        = { Name = "${var.project}-alb-sg" }
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "bedrock_endpoint" {
  name_prefix = "${var.project}-bedrock-vpce-"
  description = "Bedrock VPC endpoint - inbound from scanner only"
  vpc_id      = aws_vpc.diana.id
  tags        = { Name = "${var.project}-bedrock-vpce-sg" }
  lifecycle { create_before_destroy = true }
}

# --- Scanner Egress Rules ----------------------------------------------------

resource "aws_security_group_rule" "scanner_to_targets_80" {
  type                     = "egress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.test_targets.id
  security_group_id        = aws_security_group.scanner.id
  description              = "DVWA"
}

resource "aws_security_group_rule" "scanner_to_targets_3000" {
  type                     = "egress"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.test_targets.id
  security_group_id        = aws_security_group.scanner.id
  description              = "Juice Shop"
}

resource "aws_security_group_rule" "scanner_to_targets_8080" {
  type                     = "egress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.test_targets.id
  security_group_id        = aws_security_group.scanner.id
  description              = "WebGoat"
}

resource "aws_security_group_rule" "scanner_to_bedrock" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bedrock_endpoint.id
  security_group_id        = aws_security_group.scanner.id
  description              = "Bedrock VPC endpoint"
}

resource "aws_security_group_rule" "scanner_to_rds" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.data.id
  security_group_id        = aws_security_group.scanner.id
  description              = "RDS PostgreSQL"
}

resource "aws_security_group_rule" "scanner_to_redis" {
  type                     = "egress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.data.id
  security_group_id        = aws_security_group.scanner.id
  description              = "ElastiCache Redis"
}

resource "aws_security_group_rule" "scanner_to_s3" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  prefix_list_ids   = [aws_vpc_endpoint.s3.prefix_list_id]
  security_group_id = aws_security_group.scanner.id
  description       = "S3 gateway endpoint"
}

resource "aws_security_group_rule" "scanner_dns" {
  type              = "egress"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = [var.vpc_cidr]
  security_group_id = aws_security_group.scanner.id
  description       = "DNS resolution"
}

resource "aws_security_group_rule" "scanner_ecr_pull" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.scanner.id
  description       = "ECR pull + CloudWatch logs (via NAT)"
}

# --- Test Targets Ingress Rules (from scanner only) --------------------------

resource "aws_security_group_rule" "targets_from_scanner_80" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.test_targets.id
  description              = "DVWA from scanner"
}

resource "aws_security_group_rule" "targets_from_scanner_3000" {
  type                     = "ingress"
  from_port                = 3000
  to_port                  = 3000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.test_targets.id
  description              = "Juice Shop from scanner"
}

resource "aws_security_group_rule" "targets_from_scanner_8080" {
  type                     = "ingress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.test_targets.id
  description              = "WebGoat from scanner"
}

resource "aws_security_group_rule" "targets_ecr_pull" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.test_targets.id
  description       = "HTTPS for ECR image pull"
}

# --- Data Tier Ingress Rules (from scanner only) -----------------------------

resource "aws_security_group_rule" "data_from_scanner_pg" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.data.id
  description              = "PostgreSQL from scanner"
}

resource "aws_security_group_rule" "data_from_scanner_redis" {
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.data.id
  description              = "Redis from scanner"
}

# --- ALB Rules ---------------------------------------------------------------

resource "aws_security_group_rule" "alb_https_ingress" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidr_blocks
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from allowed CIDRs"
}

resource "aws_security_group_rule" "alb_to_scanner" {
  type                     = "egress"
  from_port                = 8000
  to_port                  = 8000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.alb.id
  description              = "To scanner containers"
}

resource "aws_security_group_rule" "scanner_from_alb" {
  type                     = "ingress"
  from_port                = 8000
  to_port                  = 8000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.alb.id
  security_group_id        = aws_security_group.scanner.id
  description              = "API traffic from ALB"
}

# --- Bedrock Endpoint Ingress ------------------------------------------------

resource "aws_security_group_rule" "bedrock_from_scanner" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.scanner.id
  security_group_id        = aws_security_group.bedrock_endpoint.id
  description              = "HTTPS from scanner"
}

# S3 Gateway Endpoint (no SG needed - uses route table)
resource "aws_vpc_endpoint" "s3" {
  vpc_id          = aws_vpc.diana.id
  service_name    = "com.amazonaws.${var.aws_region}.s3"
  route_table_ids = [aws_route_table.private.id]

  tags = {
    Name = "${var.project}-s3-vpce"
  }
}
