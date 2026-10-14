# Keys for the analytics export pipeline. Both live in Cloud HSM.

resource "google_kms_key_ring" "analytics" {
  name     = "analytics"
  location = var.region
}

resource "google_kms_crypto_key" "analytics_exports" {
  name            = "analytics-exports"
  key_ring        = google_kms_key_ring.analytics.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "release_signing" {
  name     = "release-signing"
  key_ring = google_kms_key_ring.analytics.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P384_SHA384"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "exporter" {
  crypto_key_id = google_kms_crypto_key.analytics_exports.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${var.exporter_service_account}"
}
