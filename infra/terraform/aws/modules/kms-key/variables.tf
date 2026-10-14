variable "alias" {
  description = "Alias name without the alias/ prefix."
  type        = string
}

variable "description" {
  description = "What the key protects; shown in the console."
  type        = string
}

variable "key_spec" {
  description = "Key spec of the customer managed key."
  type        = string
  default     = "SYMMETRIC_DEFAULT"
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled deletion completes."
  type        = number
  default     = 30
}

variable "user_role_arns" {
  description = "Roles allowed to use the key."
  type        = list(string)
  default     = []
}
