# External HTTPS load balancer in front of the analytics query API.

resource "google_compute_ssl_policy" "analytics_edge" {
  name            = "analytics-edge"
  profile         = "RESTRICTED"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_health_check" "analytics_api" {
  name = "analytics-api"

  http_health_check {
    port         = 8080
    request_path = "/healthz"
  }
}

resource "google_compute_backend_service" "analytics_api" {
  name                  = "analytics-api"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTP"
  port_name             = "http"
  timeout_sec           = 60
  health_checks         = [google_compute_health_check.analytics_api.id]

  # Keep a tenant's queries on the same backend so its warm cache is reused.
  locality_lb_policy = "RING_HASH"
  session_affinity   = "HEADER_FIELD"

  consistent_hash {
    http_header_name = "X-Tenant-Id"
  }

  log_config {
    enable      = true
    sample_rate = 0.2
  }
}

resource "google_compute_url_map" "analytics" {
  name            = "analytics"
  default_service = google_compute_backend_service.analytics_api.id
}

data "google_compute_ssl_certificate" "analytics" {
  name = var.analytics_cert_name
}

resource "google_compute_target_https_proxy" "analytics" {
  name             = "analytics"
  url_map          = google_compute_url_map.analytics.id
  ssl_certificates = [data.google_compute_ssl_certificate.analytics.self_link]
  ssl_policy       = google_compute_ssl_policy.analytics_edge.id
}

resource "google_compute_global_address" "analytics" {
  name = "analytics"
}

resource "google_compute_global_forwarding_rule" "analytics" {
  name                  = "analytics-https"
  target                = google_compute_target_https_proxy.analytics.id
  ip_address            = google_compute_global_address.analytics.id
  port_range            = "443"
  load_balancing_scheme = "EXTERNAL_MANAGED"
}
