data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "billing_eu" {
  name                       = "kv-tb-billing-eu"
  location                   = azurerm_resource_group.billing_eu.location
  resource_group_name        = azurerm_resource_group.billing_eu.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
  rbac_authorization_enabled = true

  network_acls {
    bypass                     = "AzureServices"
    default_action             = "Deny"
    virtual_network_subnet_ids = [azurerm_subnet.workloads.id]
  }
}

# Wraps the billing storage account's data; storage.tf points the account at it.
resource "azurerm_key_vault_key" "storage_cmk" {
  name         = "storage-cmk"
  key_vault_id = azurerm_key_vault.billing_eu.id
  key_type     = "RSA-HSM"
  key_size     = 3072
  key_opts     = ["wrapKey", "unwrapKey"]
}

# Signs EU invoices before they are sent to customers.
resource "azurerm_key_vault_key" "invoice_signing" {
  name         = "invoice-signing-eu"
  key_vault_id = azurerm_key_vault.billing_eu.id
  key_type     = "EC"
  curve        = "P-384"
  key_opts     = ["sign", "verify"]
}

resource "azurerm_user_assigned_identity" "billing_api" {
  name                = "id-billing-api"
  location            = azurerm_resource_group.billing_eu.location
  resource_group_name = azurerm_resource_group.billing_eu.name
}

resource "azurerm_role_assignment" "billing_api_signer" {
  scope                = azurerm_key_vault.billing_eu.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.billing_api.principal_id
}
