output "cluster_endpoint" {
  description = "RDS cluster writer endpoint"
  value       = aws_rds_cluster.diana.endpoint
}

output "cluster_reader_endpoint" {
  description = "RDS cluster reader endpoint"
  value       = aws_rds_cluster.diana.reader_endpoint
}

output "cluster_port" {
  description = "RDS cluster port"
  value       = aws_rds_cluster.diana.port
}

output "database_name" {
  description = "Database name"
  value       = aws_rds_cluster.diana.database_name
}
