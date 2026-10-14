"""Service settings: fixed constants, plus secrets read from the environment when first needed."""

from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Final

SERVICE_NAME: Final = "tallowbrook-reporting"
PUBLIC_BASE_URL: Final = "https://reports.tallowbrook.example"

# --- AWS ---------------------------------------------------------------------------------------

EXPORTS_REGION: Final = "us-east-2"
EXPORTS_BUCKET: Final = "tallowbrook-report-exports"
ARCHIVE_BUCKET: Final = "tallowbrook-compliance-archive"
EXPORTS_KMS_KEY_ID: Final = "alias/reporting-exports"
ARCHIVE_ESCROW_KEY_ID: Final = "alias/reporting-archive-escrow"
MANIFEST_KMS_KEY_ID: Final = "alias/reporting-manifest-signing"
ARCHIVE_KMS_KEY_ARN: Final = "arn:aws:kms:us-east-2:418302775164:alias/reporting-compliance-archive"
PRESIGNED_URL_SECONDS: Final = 900

# --- API tokens --------------------------------------------------------------------------------
# We issue RS256 API tokens; identity-go issues the ES256 ones. Both arrive at read_api_token().

TOKEN_ISSUER: Final = PUBLIC_BASE_URL
TOKEN_SIGNING_ALGORITHM: Final = "RS256"
ACCEPTED_TOKEN_ALGORITHMS: Final = ["RS256", "ES256"]
TOKEN_SIGNING_KEY_PATH: Final = "/etc/tallowbrook/pki/keys/token-signing-rs256.pem"
PLATFORM_JWKS_URL: Final = "https://identity.tallowbrook.example/.well-known/jwks.json"
PARTNER_KEYSETS_DIR: Final = Path("/etc/tallowbrook-reporting/partner-keysets")
API_TOKEN_TTL_SECONDS: Final = 3600
DOWNLOAD_TOKEN_TTL_SECONDS: Final = 900

# --- Partner file exchange ---------------------------------------------------------------------

PARTNER_API_BASE: Final = "https://partners.tallowbrook.example/v1"
PARTNER_TLS_MIN_VERSION: Final = ssl.TLSVersion.TLSv1_2
PARTNER_TLS_CIPHERS: Final = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
TLS_GROUPS_HELP_URL: Final = "https://wiki.tallowbrook.example/ops/tls-groups"
CARRIER_API_BASE: Final = "https://carriers.tallowbrook.example/api/v2"

# --- Service mesh (api-node, identity-go) ------------------------------------------------------

MESH_CLIENT_CERT: Final = "/etc/tallowbrook/pki/services/mesh-client.crt"
MESH_CLIENT_KEY: Final = "/etc/tallowbrook/pki/services/mesh-client.key"
MESH_CA_FILE: Final = "/etc/ssl/certs/tallowbrook-mesh-ca.pem"
MESH_NOTIFY_URL: Final = "https://api-node.mesh.tallowbrook.example/internal/exports"

# --- Signing material mounted from the platform secrets volume ---------------------------------

COURIER_BUNDLE_KEY_PATH: Final = "/etc/tallowbrook/pki/keys/courier-x25519.pem"
MAIL_SIGNER_CERT_PATH: Final = "/etc/tallowbrook/pki/smime/reports.crt"
MAIL_SIGNER_KEY_PATH: Final = "/etc/tallowbrook/pki/smime/reports.key"
EXPORT_SIGNER_CERT_PATH: Final = "/etc/tallowbrook/pki/signing/export-signing-p384.crt"
EXPORT_SIGNER_KEY_PATH: Final = "/etc/tallowbrook/pki/signing/export-signing-p384.key"
CUSTOMS_SIGNER_KEY_PATH: Final = "/run/secrets/customs-manifest-key.pem"

# --- CloudHSM ----------------------------------------------------------------------------------

HSM_MODULE_PATH: Final = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
HSM_TOKEN_LABEL: Final = "reporting"
HSM_KEK_LABEL: Final = "reporting-export-kek"

# --- SFTP --------------------------------------------------------------------------------------

CARRIER_SFTP_HOST: Final = "sftp.prairie-carriers.example"
CARRIER_SFTP_USER: Final = "tallowbrook"
DEPOT_SFTP_USER: Final = "reporting"
SFTP_IDENTITY_FILE: Final = "/run/secrets/sftp-identity"
DEPOT_KNOWN_HOSTS: Final = "/etc/tallowbrook-reporting/depot_known_hosts"
SFTP_DISABLED_ALGORITHMS: Final = {
    "kex": [
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
    ],
    "ciphers": ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"],
}

# --- Mail --------------------------------------------------------------------------------------

SMTP_HOST: Final = "smtp.tallowbrook.example"
SMTP_PORT: Final = 587
SMTP_USER: Final = "reporting"
REPORTS_FROM: Final = "reports@tallowbrook.example"

# --- Local state -------------------------------------------------------------------------------

DEPOTS_CONFIG: Final = Path(os.environ.get("REPORTING_DEPOTS_CONFIG", "config/depots.toml"))
TELEMETRY_STATE_DIR: Final = Path("/var/lib/tallowbrook-reporting/opcua")
TENANT_SECRETS_DIR: Final = Path("/var/lib/tallowbrook-reporting/tenants")
BLOB_CACHE_DIR: Final = Path("/var/cache/tallowbrook-reporting/blobs")
EXPORT_SPOOL_DIR: Final = Path("/var/spool/tallowbrook-reporting")


# --- Environment -------------------------------------------------------------------------------


def _env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


def download_token_secret() -> str:
    return _env("REPORTING_DOWNLOAD_TOKEN_SECRET")


def session_secret() -> str:
    return _env("REPORTING_SESSION_SECRET")


def resume_state_key() -> bytes:
    return _env("REPORTING_RESUME_STATE_KEY").encode("ascii")


def link_signing_key() -> bytes:
    return bytes.fromhex(_env("REPORTING_LINK_SIGNING_KEY"))


def export_mask_key() -> bytes:
    return bytes.fromhex(_env("REPORTING_EXPORT_MASK_KEY"))


def field_token_key() -> bytes:
    return bytes.fromhex(_env("REPORTING_FIELD_TOKEN_KEY"))


def blob_cache_key() -> bytes:
    return bytes.fromhex(_env("REPORTING_BLOB_CACHE_KEY"))


def archive_manifest_seed() -> bytes:
    return bytes.fromhex(_env("REPORTING_ARCHIVE_MANIFEST_SEED"))


def hsm_pin() -> str:
    return _env("REPORTING_HSM_PIN")


def pdf_owner_password() -> str:
    return _env("REPORTING_PDF_OWNER_PASSWORD")


def smtp_password() -> str:
    return _env("REPORTING_SMTP_PASSWORD")


def carrier_api_token() -> str:
    return _env("REPORTING_CARRIER_API_TOKEN")
