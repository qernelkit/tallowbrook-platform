resource "azurerm_resource_group" "billing_eu" {
  name     = "rg-billing-eu"
  location = var.location
}

resource "azurerm_virtual_network" "billing_eu" {
  name                = "vnet-billing-eu"
  location            = azurerm_resource_group.billing_eu.location
  resource_group_name = azurerm_resource_group.billing_eu.name
  address_space       = ["10.120.0.0/16"]
}

resource "azurerm_subnet" "workloads" {
  name                 = "workloads"
  resource_group_name  = azurerm_resource_group.billing_eu.name
  virtual_network_name = azurerm_virtual_network.billing_eu.name
  address_prefixes     = ["10.120.1.0/24"]
}

resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.billing_eu.name
  virtual_network_name = azurerm_virtual_network.billing_eu.name
  address_prefixes     = ["10.120.255.0/27"]
}
