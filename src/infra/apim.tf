# ---------------------------------------------------------------------------
# Azure API Management — AI Gateway (V10, Module 6).
#
# Off by default (var.deploy_apim) because the Developer SKU is billable and
# slow to provision (~30-45 min). When enabled it becomes the single governed
# choke point in front of the Foundry model endpoint, giving:
#   * managed-identity auth to the model (no keys in the app)
#   * token-based rate limiting (azure-openai-token-limit)
#   * token-usage metrics + centralized logging to Application Insights
# The vulnerable baseline calls the model endpoint directly (V10); the secure
# end state routes through this gateway.
# ---------------------------------------------------------------------------

resource "azurerm_api_management" "gw" {
  count               = var.deploy_apim ? 1 : 0
  name                = "apim-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  publisher_name      = var.apim_publisher_name
  publisher_email     = var.apim_publisher_email
  sku_name            = var.apim_sku

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

# APIM's managed identity must be allowed to call the Foundry model endpoint.
resource "azurerm_role_assignment" "apim_to_foundry" {
  count                = var.deploy_apim ? 1 : 0
  scope                = azurerm_cognitive_account.ai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_api_management.gw[0].identity[0].principal_id
}

resource "azurerm_api_management_logger" "appi" {
  count               = var.deploy_apim ? 1 : 0
  name                = "appinsights"
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name

  application_insights {
    instrumentation_key = azurerm_application_insights.appi.instrumentation_key
  }
}

resource "azurerm_api_management_backend" "foundry" {
  count               = var.deploy_apim ? 1 : 0
  name                = "foundry-openai"
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name
  protocol            = "http"
  url                 = "${azurerm_cognitive_account.ai.endpoint}openai"
}

resource "azurerm_api_management_api" "aoai" {
  count                 = var.deploy_apim ? 1 : 0
  name                  = "azure-openai"
  api_management_name   = azurerm_api_management.gw[0].name
  resource_group_name   = azurerm_resource_group.rg.name
  revision              = "1"
  display_name          = "Azure OpenAI (Foundry)"
  path                  = "openai"
  protocols             = ["https"]
  subscription_required = true
}

# Gateway policy: authenticate to the model with APIM's managed identity, cap
# token throughput, and emit token-usage metrics — the core V10 controls.
resource "azurerm_api_management_api_policy" "aoai" {
  count               = var.deploy_apim ? 1 : 0
  api_name            = azurerm_api_management_api.aoai[0].name
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name

  xml_content = <<XML
<policies>
  <inbound>
    <base />
    <azure-openai-token-limit tokens-per-minute="${var.ai_gateway_tpm}"
        counter-key="@(context.Subscription.Id)"
        estimate-prompt-tokens="true"
        remaining-tokens-header-name="x-ratelimit-remaining-tokens" />
    <authentication-managed-identity resource="https://cognitiveservices.azure.com" />
    <set-backend-service backend-id="${azurerm_api_management_backend.foundry[0].name}" />
  </inbound>
  <backend><base /></backend>
  <outbound>
    <base />
    <azure-openai-emit-token-metric namespace="zava-ai-gateway">
      <dimension name="Subscription" value="@(context.Subscription.Id)" />
    </azure-openai-emit-token-metric>
  </outbound>
  <on-error><base /></on-error>
</policies>
XML
}
