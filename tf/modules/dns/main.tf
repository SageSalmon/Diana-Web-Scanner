################################################################################
# Diana — DNS Module
#
# ACM certificate with DNS validation via Route 53,
# plus an alias record pointing to the ALB.
################################################################################

resource "aws_acm_certificate" "diana" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  tags = {
    Name = "${var.project}-cert"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.diana.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = var.hosted_zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]

  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "diana" {
  certificate_arn         = aws_acm_certificate.diana.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# Alias record: domain → ALB
resource "aws_route53_record" "diana" {
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
