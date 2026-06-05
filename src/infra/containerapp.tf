# ---------------------------------------------------------------------------
# Azure MCP Server (Microsoft) — the "PostgreSQL tool" for Foundry agents.
#
# Foundry's `mcp` tool only accepts a REMOTE MCP endpoint, so we self-host the
# **Microsoft Azure MCP Server** on Azure Container Apps and expose only the
# PostgreSQL namespace. It is built on the Azure SDK for .NET and authenticates
# to Azure with Microsoft Entra ID (the container's managed identity), so no
# Google / third-party SDK is involved.
#
# Image          : mcr.microsoft.com/azure-sdk/azure-mcp  (Microsoft published)
# Postgres tools : postgres list | database query | table schema get |
#                  server config/param get | server param set
# Docs           : "Deploy a self-hosted remote Azure MCP Server and connect to
#                  it using Microsoft Foundry" + "Azure Database for PostgreSQL
#                  tools for the Azure MCP Server".
#
# NOTE: the image ENTRYPOINT is fixed to `./server-binary server start`. Azure
# Container Apps `args` are APPENDED to that entrypoint (they do not replace it),
# which is the supported way to add `--transport http`, `--namespace postgres`,
# etc.
#
# Security framing for the lab:
#   * Outgoing auth uses the Container App's managed identity
#     (UseHostingEnvironmentIdentity) — give it least-privilege RBAC (V4/V8).
#   * Baseline disables incoming HTTP auth for simplicity (deliberately weak —
#     a hardened deployment would front it with Entra app auth and use the
#     Foundry project's managed identity as the audience).
#   * The Foundry MCP tool `allowed_tools` allow-list + `require_approval`
#     (set by provision_foundry_agents.py) provide the V9 / V4 controls.
# ---------------------------------------------------------------------------

resource "azurerm_container_app_environment" "mcp" {
  count                      = local.deploy_container_apps ? 1 : 0
  name                       = "cae-${local.base}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.logs.id
  tags                       = local.tags
}

resource "azurerm_container_app" "mcp_toolbox" {
  count                        = var.deploy_mcp_toolbox ? 1 : 0
  name                         = "ca-azmcp-${local.base}"
  container_app_environment_id = azurerm_container_app_environment.mcp[0].id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.tags

  # System-assigned managed identity is how the Azure MCP Server authenticates
  # to Azure (Entra ID) for all outgoing PostgreSQL / ARM requests.
  identity {
    type = "SystemAssigned"
  }

  template {
    # Keep one warm replica so Foundry MCP calls don't hit a cold start
    # (the MCP tool has a 100s non-streaming timeout).
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "azure-mcp"
      image  = var.mcp_toolbox_image
      cpu    = 0.5
      memory = "1Gi"

      # Appended to the image entrypoint (`server start`):
      #   --transport http          -> remote MCP over the ACA ingress
      #   --namespace postgres ...   -> expose only DB-related tools
      #   --outgoing-auth-strategy   -> use this container's managed identity
      #   --dangerously-disable-http-incoming-auth -> lab simplicity (see note)
      args = [
        "--transport", "http",
        "--namespace", "postgres",
        "--namespace", "group",
        "--namespace", "subscription",
        "--outgoing-auth-strategy", "UseHostingEnvironmentIdentity",
        "--dangerously-disable-http-incoming-auth",
      ]

      # The .NET server honours ASPNETCORE_URLS for its listen port.
      env {
        name  = "ASPNETCORE_URLS"
        value = "http://+:8080"
      }
      env {
        name  = "AZURE_SUBSCRIPTION_ID"
        value = data.azurerm_client_config.current.subscription_id
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8080
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [
    azurerm_postgresql_flexible_server_database.zava,
    azurerm_postgresql_flexible_server_firewall_rule.allow_azure,
  ]
}

# Browser-accessible Zava app. This is intentionally deployable in vulnerable
# mode so participants who cannot run Python locally can still do Part 1 in a
# web browser. Set app_offline_mode=false to connect the same hosted app to
# Foundry, PostgreSQL, MCP, and APIM for Part 2.
resource "azurerm_container_app" "zava_app" {
  count                        = var.deploy_app ? 1 : 0
  name                         = "ca-app-${local.base}"
  container_app_environment_id = azurerm_container_app_environment.mcp[0].id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type = "SystemAssigned"
  }

  secret {
    name  = "pg-admin-connection"
    value = "postgresql://${var.pg_admin_user}:${urlencode(var.pg_admin_password)}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/${azurerm_postgresql_flexible_server_database.zava.name}?sslmode=require"
  }

  secret {
    name  = "pg-app-connection"
    value = var.pg_app_password == "" ? "not-set" : "postgresql://${var.pg_app_user}:${urlencode(var.pg_app_password)}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/${azurerm_postgresql_flexible_server_database.zava.name}?sslmode=require"
  }

  secret {
    name  = "app-registry-password"
    value = var.app_registry_password == "" ? "not-set" : var.app_registry_password
  }

  dynamic "registry" {
    for_each = var.app_registry_server == "" ? [] : [1]
    content {
      server               = var.app_registry_server
      username             = var.app_registry_username
      password_secret_name = "app-registry-password"
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "zava-web"
      image  = var.app_container_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "OFFLINE_MODE"
        value = tostring(var.app_offline_mode)
      }
      env {
        name  = "SECURE_MODE"
        value = tostring(var.secure_mode)
      }
      env {
        name  = "FOUNDRY_PROJECT_ENDPOINT"
        value = "${azurerm_cognitive_account.ai.endpoint}api/projects/${azapi_resource.project.name}"
      }
      env {
        name  = "FOUNDRY_MODEL_DEPLOYMENT"
        value = azurerm_cognitive_deployment.governed.name
      }
      env {
        name  = "FOUNDRY_UNGOVERNED_DEPLOYMENT"
        value = var.enable_ungoverned_model ? azurerm_cognitive_deployment.ungoverned[0].name : azurerm_cognitive_deployment.governed.name
      }
      env {
        name  = "CONTENT_SAFETY_ENDPOINT"
        value = azurerm_cognitive_account.ai.endpoint
      }
      env {
        name  = "LANGUAGE_ENDPOINT"
        value = azurerm_cognitive_account.ai.endpoint
      }
      env {
        name  = "SEARCH_ENDPOINT"
        value = "https://${azurerm_search_service.search.name}.search.windows.net"
      }
      env {
        name  = "SEARCH_INDEX_NAME"
        value = "zava-financial-docs"
      }
      env {
        name  = "PG_MCP_SERVER_URL"
        value = var.deploy_mcp_toolbox ? "https://${azurerm_container_app.mcp_toolbox[0].ingress[0].fqdn}/mcp" : ""
      }
      env {
        name  = "AI_GATEWAY_URL"
        value = var.deploy_apim ? azurerm_api_management.gw[0].gateway_url : ""
      }
      env {
        name  = "VULNERABLE_APP_URL"
        value = var.vulnerable_app_url
      }
      env {
        name  = "SECURE_APP_URL"
        value = var.secure_app_url
      }
      env {
        name        = "PG_ADMIN_CONNECTION"
        secret_name = "pg-admin-connection"
      }
      env {
        name        = "PG_APP_CONNECTION"
        secret_name = "pg-app-connection"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  depends_on = [
    azurerm_postgresql_flexible_server_database.zava,
  ]
}

resource "azurerm_role_assignment" "app_to_foundry" {
  count                = var.deploy_app && !var.app_offline_mode ? 1 : 0
  scope                = azurerm_cognitive_account.ai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_container_app.zava_app[0].identity[0].principal_id
}

resource "azurerm_role_assignment" "app_to_ai_services" {
  count                = var.deploy_app && !var.app_offline_mode ? 1 : 0
  scope                = azurerm_cognitive_account.ai.id
  role_definition_name = "Cognitive Services User"
  principal_id         = azurerm_container_app.zava_app[0].identity[0].principal_id
}

resource "azurerm_role_assignment" "app_to_search" {
  count                = var.deploy_app && !var.app_offline_mode ? 1 : 0
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Index Data Reader"
  principal_id         = azurerm_container_app.zava_app[0].identity[0].principal_id
}

# Optional cohort mode: one browser-hosted app per generated lab user. This is
# useful when each participant must edit their own Foundry project/agents while
# sharing AI Search, PostgreSQL, MCP, and the APIM gateway.
resource "azurerm_container_app" "zava_user_app" {
  for_each                     = var.deploy_app && var.deploy_cohort_apps ? local.cohort_user_map : {}
  name                         = "ca-app-${local.base}-${each.value.safe_id}"
  container_app_environment_id = azurerm_container_app_environment.mcp[0].id
  resource_group_name          = azurerm_resource_group.rg.name
  revision_mode                = "Single"
  tags                         = merge(local.tags, { lab_user = each.key })

  identity {
    type = "SystemAssigned"
  }

  secret {
    name  = "pg-admin-connection"
    value = "postgresql://${var.pg_admin_user}:${urlencode(var.pg_admin_password)}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/${azurerm_postgresql_flexible_server_database.zava.name}?sslmode=require"
  }

  secret {
    name  = "pg-app-connection"
    value = var.pg_app_password == "" ? "not-set" : "postgresql://${var.pg_app_user}:${urlencode(var.pg_app_password)}@${azurerm_postgresql_flexible_server.pg.fqdn}:5432/${azurerm_postgresql_flexible_server_database.zava.name}?sslmode=require"
  }

  secret {
    name  = "app-registry-password"
    value = var.app_registry_password == "" ? "not-set" : var.app_registry_password
  }

  dynamic "registry" {
    for_each = var.app_registry_server == "" ? [] : [1]
    content {
      server               = var.app_registry_server
      username             = var.app_registry_username
      password_secret_name = "app-registry-password"
    }
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "zava-web"
      image  = var.app_container_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "ZAVA_LAB_USER"
        value = each.key
      }
      env {
        name  = "OFFLINE_MODE"
        value = tostring(var.app_offline_mode)
      }
      env {
        name  = "SECURE_MODE"
        value = tostring(var.secure_mode)
      }
      env {
        name  = "FOUNDRY_PROJECT_ENDPOINT"
        value = "${azurerm_cognitive_account.ai.endpoint}api/projects/${azapi_resource.cohort_project[each.key].name}"
      }
      env {
        name  = "FOUNDRY_MODEL_DEPLOYMENT"
        value = azurerm_cognitive_deployment.governed.name
      }
      env {
        name  = "FOUNDRY_UNGOVERNED_DEPLOYMENT"
        value = var.enable_ungoverned_model ? azurerm_cognitive_deployment.ungoverned[0].name : azurerm_cognitive_deployment.governed.name
      }
      env {
        name  = "CONTENT_SAFETY_ENDPOINT"
        value = azurerm_cognitive_account.ai.endpoint
      }
      env {
        name  = "LANGUAGE_ENDPOINT"
        value = azurerm_cognitive_account.ai.endpoint
      }
      env {
        name  = "SEARCH_ENDPOINT"
        value = "https://${azurerm_search_service.search.name}.search.windows.net"
      }
      env {
        name  = "SEARCH_INDEX_NAME"
        value = "zava-financial-docs"
      }
      env {
        name  = "PG_MCP_SERVER_URL"
        value = var.deploy_mcp_toolbox ? "https://${azurerm_container_app.mcp_toolbox[0].ingress[0].fqdn}/mcp" : ""
      }
      env {
        name  = "AI_GATEWAY_URL"
        value = var.deploy_apim ? "${azurerm_api_management.gw[0].gateway_url}/${each.value.safe_id}" : ""
      }
      env {
        name  = "VULNERABLE_APP_URL"
        value = var.vulnerable_app_url
      }
      env {
        name  = "SECURE_APP_URL"
        value = var.secure_app_url
      }
      env {
        name  = "DEFAULT_CUSTOMER_ID"
        value = each.value.customer_id
      }
      env {
        name  = "DEFAULT_OWNER_USER_ID"
        value = each.key
      }
      env {
        name        = "PG_ADMIN_CONNECTION"
        secret_name = "pg-admin-connection"
      }
      env {
        name        = "PG_APP_CONNECTION"
        secret_name = "pg-app-connection"
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}

resource "azurerm_role_assignment" "cohort_app_to_foundry" {
  for_each             = var.deploy_app && var.deploy_cohort_apps && !var.app_offline_mode ? local.cohort_user_map : {}
  scope                = azurerm_cognitive_account.ai.id
  role_definition_name = "Cognitive Services OpenAI User"
  principal_id         = azurerm_container_app.zava_user_app[each.key].identity[0].principal_id
}

resource "azurerm_role_assignment" "cohort_app_to_ai_services" {
  for_each             = var.deploy_app && var.deploy_cohort_apps && !var.app_offline_mode ? local.cohort_user_map : {}
  scope                = azurerm_cognitive_account.ai.id
  role_definition_name = "Cognitive Services User"
  principal_id         = azurerm_container_app.zava_user_app[each.key].identity[0].principal_id
}

resource "azurerm_role_assignment" "cohort_app_to_search" {
  for_each             = var.deploy_app && var.deploy_cohort_apps && !var.app_offline_mode ? local.cohort_user_map : {}
  scope                = azurerm_search_service.search.id
  role_definition_name = "Search Index Data Reader"
  principal_id         = azurerm_container_app.zava_user_app[each.key].identity[0].principal_id
}

# Least-privilege RBAC for the Azure MCP Server's managed identity: Reader on the
# resource group so it can enumerate the PostgreSQL server / databases / tables.
# (Data-plane SQL queries additionally require the identity to be a PostgreSQL
# Entra role, or the agent to supply DB credentials — see workshop notes.)
resource "azurerm_role_assignment" "mcp_reader" {
  count                = var.deploy_mcp_toolbox ? 1 : 0
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Reader"
  principal_id         = azurerm_container_app.mcp_toolbox[0].identity[0].principal_id
}
