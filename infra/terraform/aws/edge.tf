# Public entry points: the API load balancer (customers and carrier EDI), the
# driver tracking NLB, the partner API Gateway domain and the CloudFront site.
# Validation records for the ACM requests are published by the dns stack.

resource "aws_acm_certificate" "api" {
  domain_name               = "api.tallowbrook.example"
  subject_alternative_names = ["partners.tallowbrook.example", "tracking.tallowbrook.example"]
  validation_method         = "DNS"
  key_algorithm             = "EC_secp384r1"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate" "cdn" {
  provider = aws.us_east_1

  domain_name               = "www.tallowbrook.example"
  subject_alternative_names = ["tallowbrook.example"]
  validation_method         = "DNS"
  key_algorithm             = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }
}

# ---------------------------------------------------------------- API load balancer

resource "aws_lb" "api" {
  name                       = "api-${var.environment}"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.public_lb.id]
  drop_invalid_header_fields = true
  idle_timeout               = 120

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    prefix  = "api"
    enabled = true
  }
}

resource "aws_lb_target_group" "api" {
  name                          = "api-gateway"
  port                          = 8080
  protocol                      = "HTTP"
  vpc_id                        = aws_vpc.main.id
  target_type                   = "ip"
  load_balancing_algorithm_type = "least_outstanding_requests"
  deregistration_delay          = 30

  health_check {
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
  }
}

resource "aws_lb_target_group" "carrier" {
  name        = "carrier-edi"
  port        = 8081
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path = "/edi/healthz"
  }
}

resource "aws_lb_listener" "api_https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
  certificate_arn   = aws_acm_certificate.api.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# Carrier EDI partners connect on 8443. Two of them still run AS2 software that
# cannot be upgraded before the contract renewals, so this listener keeps the
# broad policy until then (see docs/security/tls-policy.md).
resource "aws_lb_listener" "carrier_https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.api.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.carrier.arn
  }
}

# ---------------------------------------------------------------- driver tracking NLB

resource "aws_lb" "tracking" {
  name               = "tracking-${var.environment}"
  load_balancer_type = "network"
  internal           = false
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "tracking" {
  name        = "tracking-ingest"
  port        = 7443
  protocol    = "TCP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"
}

resource "aws_lb_listener" "tracking_tls" {
  load_balancer_arn = aws_lb.tracking.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = var.tracking_tls_policy
  certificate_arn   = aws_acm_certificate.api.arn
  alpn_policy       = "HTTP2Preferred"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tracking.arn
  }
}

# ---------------------------------------------------------------- partner API Gateway

resource "aws_api_gateway_domain_name" "partner_api" {
  domain_name              = "partners.tallowbrook.example"
  regional_certificate_arn = aws_acm_certificate.api.arn
  security_policy          = "TLS_1_2"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_route53_record" "partner_api" {
  zone_id = var.route53_zone_id
  name    = aws_api_gateway_domain_name.partner_api.domain_name
  type    = "A"

  alias {
    name                   = aws_api_gateway_domain_name.partner_api.regional_domain_name
    zone_id                = aws_api_gateway_domain_name.partner_api.regional_zone_id
    evaluate_target_health = false
  }
}

# ---------------------------------------------------------------- CloudFront

resource "aws_cloudfront_origin_access_identity" "static_assets" {
  comment = "www.tallowbrook.example static assets"
}

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_distribution" "www" {
  enabled             = true
  is_ipv6_enabled     = true
  aliases             = ["www.tallowbrook.example", "tallowbrook.example"]
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    domain_name = aws_s3_bucket.static_assets.bucket_regional_domain_name
    origin_id   = "static-assets"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.static_assets.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    target_origin_id       = "static-assets"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cdn.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
