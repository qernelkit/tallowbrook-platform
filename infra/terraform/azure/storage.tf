resource "azurerm_storage_account" "billing_eu" {
  name                            = "tbbillingeu"
  resource_group_name             = azurerm_resource_group.billing_eu.name
  location                        = azurerm_resource_group.billing_eu.location
  account_tier                    = "Standard"
  account_replication_type        = "ZRS"
  min_tls_version                 = var.storage_min_tls_version
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false

  identity {
    type = "SystemAssigned"
  }

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }
  }
}

resource "azurerm_role_assignment" "storage_cmk" {
  scope                = azurerm_key_vault.billing_eu.id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_storage_account.billing_eu.identity[0].principal_id
}

resource "azurerm_storage_account_customer_managed_key" "billing_eu" {
  storage_account_id = azurerm_storage_account.billing_eu.id
  key_vault_key_id   = azurerm_key_vault_key.storage_cmk.id

  depends_on = [azurerm_role_assignment.storage_cmk]
}

resource "azurerm_storage_container" "invoices" {
  name                  = "invoices"
  storage_account_id    = azurerm_storage_account.billing_eu.id
  container_access_type = "private"
}
