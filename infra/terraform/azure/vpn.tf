# Site-to-site VPN to the Frankfurt depot.

resource "azurerm_public_ip" "vpn_gateway" {
  name                = "pip-vpn-billing-eu"
  location            = azurerm_resource_group.billing_eu.location
  resource_group_name = azurerm_resource_group.billing_eu.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
}

resource "azurerm_virtual_network_gateway" "billing_eu" {
  name                = "vgw-billing-eu"
  location            = azurerm_resource_group.billing_eu.location
  resource_group_name = azurerm_resource_group.billing_eu.name
  type                = "Vpn"
  vpn_type            = "RouteBased"
  sku                 = "VpnGw2AZ"
  generation          = "Generation2"

  ip_configuration {
    name                 = "default"
    public_ip_address_id = azurerm_public_ip.vpn_gateway.id
    subnet_id            = azurerm_subnet.gateway.id
  }
}

resource "azurerm_local_network_gateway" "depot_fra" {
  name                = "lgw-depot-fra"
  location            = azurerm_resource_group.billing_eu.location
  resource_group_name = azurerm_resource_group.billing_eu.name
  gateway_address     = var.depot_fra_public_ip
  address_space       = [var.depot_fra_cidr]
}

resource "azurerm_virtual_network_gateway_connection" "depot_fra" {
  name                       = "depot-fra"
  location                   = azurerm_resource_group.billing_eu.location
  resource_group_name        = azurerm_resource_group.billing_eu.name
  type                       = "IPsec"
  virtual_network_gateway_id = azurerm_virtual_network_gateway.billing_eu.id
  local_network_gateway_id   = azurerm_local_network_gateway.depot_fra.id
  shared_key                 = "Iiw9KBnT5U7tY5AQUOPublOh1aoJqNvNOmEg3Gii"
}
