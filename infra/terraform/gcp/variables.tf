variable "project_id" {
  description = "Analytics project."
  type        = string
  default     = "tb-analytics-prod"
}

variable "region" {
  description = "Region of the analytics pipeline."
  type        = string
  default     = "us-central1"
}

variable "exporter_service_account" {
  description = "Service account of the analytics export job."
  type        = string
  default     = "analytics-exporter@tb-analytics-prod.iam.gserviceaccount.com"
}

variable "analytics_cert_name" {
  description = "Name of the server cert the PKI team uploads for analytics.tallowbrook.example."
  type        = string
  default     = "analytics-tallowbrook-2026"
}
