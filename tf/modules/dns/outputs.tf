output "certificate_arn" {
  description = "ACM certificate ARN (validated)"
  value       = aws_acm_certificate_validation.diana.certificate_arn
}

output "fqdn" {
  description = "FQDN for Diana API"
  value       = aws_route53_record.diana.fqdn
}
