variable "subscription_id" {
  description = "EU billing subscription."
  type        = string
  default     = "8f14e45f-ceea-467f-a8f5-3c1e2a7b9d40"
}

variable "location" {
  description = "Azure region for EU billing."
  type        = string
  default     = "germanywestcentral"
}

variable "storage_min_tls_version" {
  description = "Lowest protocol version the billing storage account accepts."
  type        = string
  default     = "TLS1_2"
}

variable "depot_fra_public_ip" {
  description = "Public address of the FRA depot firewall."
  type        = string
  default     = "192.0.2.77"
}

variable "depot_fra_cidr" {
  description = "Internal range behind the FRA depot firewall."
  type        = string
  default     = "10.90.0.0/20"
}
