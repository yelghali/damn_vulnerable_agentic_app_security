# ---------------------------------------------------------------------------
# Monitoring (V7) — Log Analytics + Application Insights.
# In the vulnerable baseline these exist but nothing is wired to them; Module 6
# connects diagnostic settings + Defender for Cloud AI threat protection.
# ---------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "logs" {
  name                = "log-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_application_insights" "appi" {
  name                = "appi-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  workspace_id        = azurerm_log_analytics_workspace.logs.id
  application_type    = "web"
  tags                = local.tags
}
