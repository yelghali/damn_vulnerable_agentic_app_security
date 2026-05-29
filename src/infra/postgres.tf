# ---------------------------------------------------------------------------
# PostgreSQL Flexible Server (V4) — backs the data tools (get_accounts,
# get_transactions, get_credit_score, transfer_funds).
#
# Baseline vulnerability: the app connects with the admin login (full
# read/write/DDL). Module 4 adds a least-privilege role + row-level security;
# that role is created by the seed SQL, not here.
# ---------------------------------------------------------------------------

resource "azurerm_postgresql_flexible_server" "pg" {
  name                = "pg-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  version                = "16"
  administrator_login    = var.pg_admin_user
  administrator_password = var.pg_admin_password
  sku_name               = var.pg_sku_name
  storage_mb             = 32768
  zone                   = "1"

  # V7: public access in baseline; in secure mode disable it and use a private
  # endpoint / VNet integration (Module 6).
  public_network_access_enabled = local.public_network_access

  tags = local.tags

  lifecycle {
    ignore_changes = [zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "zava" {
  name      = "zava"
  server_id = azurerm_postgresql_flexible_server.pg.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# LAB-VULN(V7): baseline opens the server to all Azure services + (optionally)
# the deployer's IP so the workshop can seed it. Only created when NOT secure.
resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure" {
  count            = var.secure_mode ? 0 : 1
  name             = "allow-azure-services"
  server_id        = azurerm_postgresql_flexible_server.pg.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}
