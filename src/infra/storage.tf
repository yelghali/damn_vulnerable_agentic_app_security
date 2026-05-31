# ---------------------------------------------------------------------------
# Storage (V6) — Blob container holding the source financial documents that are
# ingested into the AI Search RAG index. One container also carries the
# deliberately poisoned doc used in Modules 2 & 8 (indirect prompt injection).
# ---------------------------------------------------------------------------

resource "azurerm_storage_account" "docs" {
  name                     = "st${local.base}"
  location                 = azurerm_resource_group.rg.location
  resource_group_name      = azurerm_resource_group.rg.name
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Subscription policy denies shared-key auth; use Entra (AAD) only.
  shared_access_key_enabled = false

  # V7: public blob/network access open in baseline, disabled in secure mode.
  public_network_access_enabled   = local.public_network_access
  allow_nested_items_to_be_public = false

  tags = local.tags
}

# The deployer needs data-plane access (AAD) to create the container and upload
# the seed documents, since shared-key auth is disabled.
resource "azurerm_role_assignment" "storage_blob_contributor" {
  scope                = azurerm_storage_account.docs.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_storage_container" "documents" {
  name                  = "documents"
  storage_account_id    = azurerm_storage_account.docs.id
  container_access_type = "private"

  depends_on = [azurerm_role_assignment.storage_blob_contributor]
}
