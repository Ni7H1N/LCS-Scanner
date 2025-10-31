provider "azurerm" {
  features {}
}

resource "azurerm_network_security_group" "open_nsg" {
  name                = "open-nsg"
  location            = "East US"
  resource_group_name = "example-resources"

  security_rule {
    name                       = "AllowAll"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_storage_account" "unencrypted" {
  name                     = "unsecurestorage123"
  resource_group_name      = "example-resources"
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  enable_https_traffic_only = false
}
