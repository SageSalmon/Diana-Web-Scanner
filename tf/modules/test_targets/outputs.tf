output "juice_shop_dns" {
  description = "Juice Shop service discovery DNS name"
  value       = "juice-shop.${aws_service_discovery_private_dns_namespace.targets.name}"
}

output "dvwa_dns" {
  description = "DVWA service discovery DNS name"
  value       = "dvwa.${aws_service_discovery_private_dns_namespace.targets.name}"
}

output "webgoat_dns" {
  description = "WebGoat service discovery DNS name"
  value       = "webgoat.${aws_service_discovery_private_dns_namespace.targets.name}"
}

output "namespace_id" {
  description = "Service discovery namespace ID"
  value       = aws_service_discovery_private_dns_namespace.targets.id
}
