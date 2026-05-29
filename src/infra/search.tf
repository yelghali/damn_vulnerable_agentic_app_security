# ---------------------------------------------------------------------------
# Azure AI Search (V5/V6) — vector index for RAG over the financial documents.
# Document-level security trimming (Module 5) filters results by the caller's
# group_ids via search.in(); the service is provisioned here, the index +
# security filter are created by the seed script.
# ---------------------------------------------------------------------------

resource "azurerm_search_service" "search" {
  name                = "srch-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = var.search_sku

  # Managed-identity auth is preferred; local (key) auth stays on in the
  # baseline so the vulnerable app can use an admin key.
  local_authentication_enabled = var.secure_mode ? false : true

  # V7: lock the data plane down in secure mode.
  public_network_access_enabled = local.public_network_access

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}
