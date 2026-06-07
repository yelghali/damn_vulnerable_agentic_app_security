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

# Container Apps already streams console logs to the workspace through the
# managed environment. Diagnostic settings make platform logs/metrics explicit
# for Module 6 and keep ACA observability beside APIM/model traces.
resource "azurerm_monitor_diagnostic_setting" "aca_environment" {
  count                      = local.deploy_container_apps ? 1 : 0
  name                       = "diag-${local.base}-aca"
  target_resource_id         = azurerm_container_app_environment.mcp[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id

  enabled_log {
    category = "ContainerAppConsoleLogs"
  }

  enabled_log {
    category = "ContainerAppSystemLogs"
  }

  enabled_log {
    category = "ContainerAppHTTPLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
