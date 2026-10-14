# Vault server configuration (mounted into the vault StatefulSet from the
# vault-config ConfigMap). Raft storage, auto-unseal through AWS KMS.

# cluster_addr comes from VAULT_CLUSTER_ADDR, set per pod by the StatefulSet.
ui            = true
cluster_name  = "tb-prod"
api_addr      = "https://vault.internal.tallowbrook.example:8200"
disable_mlock = true

storage "raft" {
  path = "/vault/data"

  retry_join {
    leader_api_addr     = "https://vault-0.vault-internal:8200"
    leader_ca_cert_file = "/vault/userconfig/vault-server-tls/ca.crt"
  }

  retry_join {
    leader_api_addr     = "https://vault-1.vault-internal:8200"
    leader_ca_cert_file = "/vault/userconfig/vault-server-tls/ca.crt"
  }

  retry_join {
    leader_api_addr     = "https://vault-2.vault-internal:8200"
    leader_ca_cert_file = "/vault/userconfig/vault-server-tls/ca.crt"
  }
}

listener "tcp" {
  address         = "[::]:8200"
  cluster_address = "[::]:8201"
  tls_cert_file   = "/vault/userconfig/vault-server-tls/tls.crt"
  tls_key_file    = "/vault/userconfig/vault-server-tls/tls.key"
  tls_min_version = "tls13"

  telemetry {
    unauthenticated_metrics_access = true
  }
}

seal "awskms" {
  region     = "us-east-2"
  kms_key_id = "alias/tb-vault-unseal"
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
