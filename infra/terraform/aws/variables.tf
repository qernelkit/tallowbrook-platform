variable "environment" {
  description = "Deployment environment name, used in names and tags."
  type        = string
  default     = "prod"
}

variable "region" {
  description = "Primary AWS region."
  type        = string
  default     = "us-east-2"
}

variable "vpc_cidr" {
  description = "Address range of the platform VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "One public subnet per availability zone, for the load balancers."
  type        = list(string)
  default     = ["10.40.0.0/22", "10.40.4.0/22", "10.40.8.0/22"]
}

variable "private_subnet_cidrs" {
  description = "One private subnet per availability zone, for workloads and data stores."
  type        = list(string)
  default     = ["10.40.32.0/20", "10.40.48.0/20", "10.40.64.0/20"]
}

variable "availability_zones" {
  description = "Availability zones used by the subnets, in order."
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b", "us-east-2c"]
}

variable "office_cidrs" {
  description = "Office egress ranges allowed to reach the bastion."
  type        = list(string)
  default     = ["203.0.113.32/28"]
}

variable "depot_ord_public_ip" {
  description = "Public address of the ORD depot firewall."
  type        = string
  default     = "198.51.100.24"
}

variable "depot_ord_cidr" {
  description = "Internal range behind the ORD depot firewall."
  type        = string
  default     = "10.80.0.0/20"
}

variable "tracking_tls_policy" {
  description = "Listener policy for the driver tracking endpoint on the NLB."
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-3-2021-06"
}

variable "kmsuser_password" {
  description = "Password of the kmsuser crypto user on the payments CloudHSM cluster."
  type        = string
  sensitive   = true
}

variable "route53_zone_id" {
  description = "Hosted zone of tallowbrook.example."
  type        = string
  default     = "Z04417262K7QXAMPLE1Z"
}
