output "key_arn" {
  description = "ARN of the key."
  value       = aws_kms_key.this.arn
}

output "key_id" {
  description = "Key ID, for services that want the bare ID."
  value       = aws_kms_key.this.key_id
}

output "alias_name" {
  description = "Full alias name."
  value       = aws_kms_alias.this.name
}
