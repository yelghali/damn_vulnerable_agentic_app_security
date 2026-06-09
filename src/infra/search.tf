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

  # Enable Entra (RBAC) auth alongside keys so the provisioning script and
  # agents can use DefaultAzureCredential (keyless). Setting the failure mode
  # switches the service from apiKeyOnly to aadOrApiKey.
  authentication_failure_mode = "http403"

  # V7: lock the data plane down in secure mode.
  public_network_access_enabled = local.public_network_access

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

# Foundry Agent Service AI Search tools use keyless Entra auth through the
# project managed identity. Grant it the roles required by the Foundry AI Search
# tool so portal-visible agents can query the index without an admin key.
resource "azurerm_role_assignment" "foundry_project_search_data" {
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Index Data Contributor"
  principal_id         = azapi_resource.project.identity[0].principal_id
}

resource "azurerm_role_assignment" "foundry_project_search_service" {
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Service Contributor"
  principal_id         = azapi_resource.project.identity[0].principal_id
}
