# ---------------------------------------------------------------------------
# Outputs — non-secret values the deploy/seed scripts and .env need. Secrets
# (keys, connection strings) are written to Key Vault by the deploy script, not
# emitted here.
# ---------------------------------------------------------------------------

output "resource_group" {
  value = azurerm_resource_group.rg.name
}

output "location" {
  value = azurerm_resource_group.rg.location
}

output "foundry_account_name" {
  value = azurerm_cognitive_account.ai.name
}

output "foundry_endpoint" {
  description = "AIServices endpoint used by the Foundry project SDK."
  value       = azurerm_cognitive_account.ai.endpoint
}

output "foundry_project_name" {
  value = azapi_resource.project.name
}

output "model_deployment_governed" {
  value = azurerm_cognitive_deployment.governed.name
}

output "model_deployment_ungoverned" {
  description = "V1 simulated-unsafe deployment (content filters off). Falls back to the governed deployment when enable_ungoverned_model = false (restricted subscriptions)."
  value       = var.enable_ungoverned_model ? azurerm_cognitive_deployment.ungoverned[0].name : azurerm_cognitive_deployment.governed.name
}

output "search_endpoint" {
  value = "https://${azurerm_search_service.search.name}.search.windows.net"
}

output "storage_account_name" {
  value = azurerm_storage_account.docs.name
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.pg.fqdn
}

output "postgres_database" {
  value = azurerm_postgresql_flexible_server_database.zava.name
}

output "key_vault_name" {
  value = azurerm_key_vault.kv.name
}

output "application_insights_connection_string" {
  value     = azurerm_application_insights.appi.connection_string
  sensitive = true
}

output "ai_gateway_url" {
  description = "APIM AI Gateway base URL (empty until deploy_apim = true)."
  value       = var.deploy_apim ? azurerm_api_management.gw[0].gateway_url : ""
}

output "pg_mcp_server_url" {
  description = "Remote MCP endpoint (Microsoft Azure MCP Server) that Foundry agents attach as their PostgreSQL tool. Empty when deploy_mcp_toolbox = false."
  value       = var.deploy_mcp_toolbox ? "https://${azurerm_container_app.mcp_toolbox[0].ingress[0].fqdn}/mcp" : ""
}

output "app_url" {
  description = "Browser URL for the Zava vulnerable/secure app when deploy_app = true."
  value       = var.deploy_app ? "https://${azurerm_container_app.zava_app[0].ingress[0].fqdn}" : ""
}

output "secure_mode" {
  description = "Infra security posture this state was applied with."
  value       = var.secure_mode
}
