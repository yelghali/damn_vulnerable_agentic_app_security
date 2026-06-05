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

resource "azurerm_api_management_named_value" "foundry_key" {
  count               = var.deploy_apim ? 1 : 0
  name                = "foundry-openai-key"
  display_name        = "foundry-openai-key"
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name
  secret              = true
  value               = azurerm_cognitive_account.ai.primary_access_key
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
  subscription_required = false
}

resource "azurerm_api_management_api_operation" "chat_completions" {
  count               = var.deploy_apim ? 1 : 0
  operation_id        = "chat-completions"
  api_name            = azurerm_api_management_api.aoai[0].name
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name
  display_name        = "Chat completions"
  method              = "POST"
  url_template        = "/deployments/{deploymentId}/chat/completions"

  template_parameter {
    name     = "deploymentId"
    required = true
    type     = "string"
  }

  request {
    representation {
      content_type = "application/json"
    }
  }

  response {
    status_code = 200
  }
}

# Gateway policy: keep the app keyless by storing the Foundry key in APIM,
# then rate-limit requests at the gateway. This keeps the deployed workshop
# path portable across APIM SKUs while still making APIM the central V10 control.
resource "azurerm_api_management_api_policy" "aoai" {
  count               = var.deploy_apim ? 1 : 0
  api_name            = azurerm_api_management_api.aoai[0].name
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name

  xml_content = <<XML
<policies>
  <inbound>
    <base />
    <rate-limit-by-key calls="120" renewal-period="60" counter-key="@(context.Request.IpAddress)" />
    <set-header name="Authorization" exists-action="delete" />
    <set-header name="api-key" exists-action="override">
      <value>{{foundry-openai-key}}</value>
    </set-header>
    <set-backend-service backend-id="${azurerm_api_management_backend.foundry[0].name}" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
XML
}

# Optional cohort mode: keep one shared APIM service, but create a separate API
# surface per lab user. Each participant can safely edit their own API policy
# (rate limits, auth, logging) without changing another user's route.
resource "azurerm_api_management_api" "cohort_aoai" {
  for_each              = var.deploy_apim ? local.cohort_user_map : {}
  name                  = "azure-openai-${each.value.safe_id}"
  api_management_name   = azurerm_api_management.gw[0].name
  resource_group_name   = azurerm_resource_group.rg.name
  revision              = "1"
  display_name          = "Azure OpenAI (Foundry) - ${each.key}"
  path                  = "${each.value.safe_id}/openai"
  protocols             = ["https"]
  subscription_required = false
}

resource "azurerm_api_management_api_operation" "cohort_chat_completions" {
  for_each            = var.deploy_apim ? local.cohort_user_map : {}
  operation_id        = "chat-completions"
  api_name            = azurerm_api_management_api.cohort_aoai[each.key].name
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name
  display_name        = "Chat completions"
  method              = "POST"
  url_template        = "/deployments/{deploymentId}/chat/completions"

  template_parameter {
    name     = "deploymentId"
    required = true
    type     = "string"
  }

  request {
    representation {
      content_type = "application/json"
    }
  }

  response {
    status_code = 200
  }
}

resource "azurerm_api_management_api_policy" "cohort_aoai" {
  for_each            = var.deploy_apim ? local.cohort_user_map : {}
  api_name            = azurerm_api_management_api.cohort_aoai[each.key].name
  api_management_name = azurerm_api_management.gw[0].name
  resource_group_name = azurerm_resource_group.rg.name

  xml_content = <<XML
<policies>
  <inbound>
    <base />
    <rate-limit-by-key calls="60" renewal-period="60" counter-key="${each.key}" />
    <set-header name="x-zava-lab-user" exists-action="override">
      <value>${each.key}</value>
    </set-header>
    <set-header name="Authorization" exists-action="delete" />
    <set-header name="api-key" exists-action="override">
      <value>{{foundry-openai-key}}</value>
    </set-header>
    <set-backend-service backend-id="${azurerm_api_management_backend.foundry[0].name}" />
  </inbound>
  <backend><base /></backend>
  <outbound><base /></outbound>
  <on-error><base /></on-error>
</policies>
XML
}
