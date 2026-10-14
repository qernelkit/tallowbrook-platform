# Buckets owned by the platform team, and the export job table.

locals {
  buckets = {
    exports       = "tb-partner-exports-${var.environment}"
    static_assets = "tb-www-assets-${var.environment}"
    db_backups    = "tb-db-backups-${var.environment}"
    lb_logs       = "tb-lb-logs-${var.environment}"
  }
}

resource "aws_s3_bucket" "exports" {
  bucket = local.buckets.exports
}

resource "aws_s3_bucket" "static_assets" {
  bucket = local.buckets.static_assets
}

resource "aws_s3_bucket" "db_backups" {
  bucket = local.buckets.db_backups
}

resource "aws_s3_bucket" "lb_logs" {
  bucket = local.buckets.lb_logs
}

resource "aws_s3_bucket_public_access_block" "all" {
  for_each = {
    exports       = aws_s3_bucket.exports.id
    static_assets = aws_s3_bucket.static_assets.id
    db_backups    = aws_s3_bucket.db_backups.id
    lb_logs       = aws_s3_bucket.lb_logs.id
  }

  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "db_backups" {
  bucket = aws_s3_bucket.db_backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "exports" {
  bucket = aws_s3_bucket.exports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    id     = "expire-delivered-bundles"
    status = "Enabled"

    filter {
      prefix = "outbound/"
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "db_backups" {
  bucket = aws_s3_bucket.db_backups.id

  rule {
    id     = "nightly-to-glacier"
    status = "Enabled"

    filter {
      prefix = "nightly/"
    }

    transition {
      days          = 35
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 400
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.export_data_key.key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "db_backups" {
  bucket = aws_s3_bucket.db_backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms:dsse"
      kms_master_key_id = module.backups_key.key_arn
    }
  }
}

data "aws_iam_policy_document" "static_assets" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.static_assets.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.static_assets.iam_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "static_assets" {
  bucket = aws_s3_bucket.static_assets.id
  policy = data.aws_iam_policy_document.static_assets.json
}

data "aws_iam_policy_document" "lb_logs" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lb_logs.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "lb_logs" {
  bucket = aws_s3_bucket.lb_logs.id
  policy = data.aws_iam_policy_document.lb_logs.json
}

# Export job bookkeeping for the partner export worker.
resource "aws_dynamodb_table" "export_jobs" {
  name         = "export-jobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "TenantId"
  range_key    = "JobId"

  attribute {
    name = "TenantId"
    type = "S"
  }

  attribute {
    name = "JobId"
    type = "S"
  }

  ttl {
    attribute_name = "ExpiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }
}
