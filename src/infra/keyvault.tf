# ---------------------------------------------------------------------------
# Key Vault (V5) — secret store for connection strings / keys. RBAC-authorized
# (no access policies). The deploy script writes secrets here; the app reads
# them via managed identity in secure mode instead of env vars.
# ---------------------------------------------------------------------------

resource "azurerm_key_vault" "kv" {
  name                       = "kv-${local.base}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  # V7: open in baseline, restricted in secure mode (pair with private endpoint).
  public_network_access_enabled = local.public_network_access

  tags = local.tags
}

# Let the deployer manage secrets (write seed values) during provisioning.
resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}
