# Reporting database (PostgreSQL 17) used by reporting-python and the BI tools.

resource "aws_db_subnet_group" "reporting" {
  name       = "reporting"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "reporting_pg17" {
  name        = "reporting-pg17"
  family      = "postgres17"
  description = "Reporting database settings"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.3"
  }

  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }

  parameter {
    name  = "idle_in_transaction_session_timeout"
    value = "600000"
  }
}

resource "aws_db_instance" "reporting" {
  identifier                  = "reporting-${var.environment}"
  engine                      = "postgres"
  engine_version              = "17.5"
  instance_class              = "db.r7g.large"
  allocated_storage           = 200
  max_allocated_storage       = 1000
  storage_type                = "gp3"
  storage_encrypted           = true
  kms_key_id                  = module.reporting_db_key.key_arn
  db_name                     = "reporting"
  username                    = "reporting_admin"
  manage_master_user_password = true
  parameter_group_name        = aws_db_parameter_group.reporting_pg17.name
  db_subnet_group_name        = aws_db_subnet_group.reporting.name
  vpc_security_group_ids      = [aws_security_group.reporting_db.id]
  multi_az                    = true
  backup_retention_period     = 14
  backup_window               = "06:00-07:00"
  maintenance_window          = "sun:07:30-sun:08:30"
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "reporting-${var.environment}-final"
  auto_minor_version_upgrade  = true
}
