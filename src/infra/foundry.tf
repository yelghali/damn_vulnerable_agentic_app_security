# ---------------------------------------------------------------------------
# Azure AI Foundry (V1/V2) — the AIServices account hosts the models, the
# Content Safety / Prompt Shields features, and the Foundry project that the
# app talks to via the Foundry project SDK (azure-ai-projects >= 2.0.0).
#
# Two model deployments are created so the lab can contrast them:
#   * governed   — attaches the "governed" RAI policy below: low-threshold
#                  content filters + Prompt Shields (Jailbreak + Indirect
#                  Attack). This is the SERVER-SIDE Foundry guardrail and is the
#                  secure end state. It is provisioned declaratively here, not
#                  in Python — the app cannot bypass it.
#   * ungoverned — a custom RAI policy with filters effectively OFF, which
#                  SAFELY simulates the V1 "unsafe model" without hosting a
#                  genuinely unsafe model.
#
# The Content Safety SDK calls in src/agents/guard/guard.py are defense-in-depth
# layered ON TOP of the platform policy (e.g. per-RAG-document shielding for V6
# and tool-output re-checks the deployment filter never sees).
# ---------------------------------------------------------------------------

resource "azurerm_cognitive_account" "ai" {
  name                = "aif-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "AIServices"
  sku_name            = "S0"

  # Required for token-based (Entra) auth + model deployments.
  custom_subdomain_name = "aif-${local.base}"

  # Foundry projects require allowProjectManagement = true on the account.
  # Set it here (the provider manages this property); the azapi_update below is
  # kept as a belt-and-braces patch for older provider versions.
  project_management_enabled = true

  # Local (key) auth stays enabled in the baseline; secure mode forces Entra.
  local_auth_enabled = var.secure_mode ? false : true

  # V7: public network access open in baseline, disabled in secure mode.
  public_network_access_enabled = local.public_network_access

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

# Foundry projects can only be created when the AIServices account has
# allowProjectManagement = true. azurerm doesn't expose this property yet, so
# patch it onto the account via azapi before the project is created.
resource "azapi_update_resource" "ai_allow_projects" {
  type        = "Microsoft.CognitiveServices/accounts@2025-04-01-preview"
  resource_id = azurerm_cognitive_account.ai.id

  body = {
    properties = {
      allowProjectManagement = true
    }
  }
}

# --- Governed RAI policy: the SERVER-SIDE Foundry guardrail (Module 1 + 2) ----
# This is the genuine platform control the app cannot bypass. It is provisioned
# DECLARATIVELY here (not in Python): harmful-content filters block at a low
# severity threshold, and Prompt Shields are turned on for BOTH direct
# (Jailbreak) and indirect (Indirect Attack) prompt-injection, plus Protected
# Material. The app-side Content Safety calls in src/agents/guard/guard.py are
# defense-in-depth on top of this — notably the only place that can shield each
# RETRIEVED RAG document (V6) and re-check tool output, which the deployment
# filter never sees.
resource "azapi_resource" "rai_governed" {
  type      = "Microsoft.CognitiveServices/accounts/raiPolicies@2024-10-01"
  name      = "governed"
  parent_id = azurerm_cognitive_account.ai.id

  body = {
    properties = {
      basePolicyName = "Microsoft.DefaultV2"
      mode           = "Default"
      contentFilters = concat(
        [
          for entry in setproduct(["Hate", "Sexual", "Violence", "Selfharm"], ["Prompt", "Completion"]) : {
            name              = entry[0]
            blocking          = true
            enabled           = true
            severityThreshold = var.content_filter_severity_threshold
            source            = entry[1]
          }
        ],
        [
          # Prompt Shields — direct jailbreak detection on the user prompt (V2).
          { name = "Jailbreak", blocking = true, enabled = true, source = "Prompt" },
          # Prompt Shields — indirect injection detection on grounding docs (V6).
          { name = "Indirect Attack", blocking = true, enabled = true, source = "Prompt" },
          # Protected material (completion-side).
          { name = "Protected Material Text", blocking = true, enabled = true, source = "Completion" },
        ]
      )
    }
  }

  schema_validation_enabled = false
}

# --- Governed deployment: default content filters (secure reference) ---------
resource "azurerm_cognitive_deployment" "governed" {
  name                 = "gpt-governed"
  cognitive_account_id = azurerm_cognitive_account.ai.id

  # Attach the server-side guardrail policy above (Prompt Shields + low-threshold
  # content filters). In secure_mode this is the policy the app actually uses;
  # the default Microsoft policy is the fallback when not in secure mode.
  rai_policy_name = var.secure_mode ? azapi_resource.rai_governed.name : null

  model {
    format  = "OpenAI"
    name    = var.model_name
    version = var.model_version
  }

  sku {
    name     = "GlobalStandard"
    capacity = var.model_deployment_capacity
  }
}

resource "azurerm_cognitive_deployment" "governed_pool" {
  for_each             = toset([for index in range(2, var.model_deployment_pool_size + 1) : format("gpt-governed-%02d", index)])
  name                 = each.value
  cognitive_account_id = azurerm_cognitive_account.ai.id
  rai_policy_name      = var.secure_mode ? azapi_resource.rai_governed.name : null

  model {
    format  = "OpenAI"
    name    = var.model_name
    version = var.model_version
  }

  sku {
    name     = "GlobalStandard"
    capacity = var.model_deployment_capacity
  }
}

locals {
  governed_model_deployment_pool = concat(
    [azurerm_cognitive_deployment.governed.name],
    [for deployment in azurerm_cognitive_deployment.governed_pool : deployment.name]
  )
}

# --- Custom RAI policy with filters OFF (simulates the ungoverned model) ------
# LAB-VULN(V1): this policy disables the harmful-content filters. It exists only
# to make the "before" state reproducible and is never used by the secure app.
# Disabling base content filters requires an approved modified-content-filter
# exception on the subscription (aka.ms/oai/rai/exceptions). Many sponsored /
# managed subscriptions don't have it, so this is gated off by default. The V1
# "unsafe model" demo is also reproducible in OFFLINE_MODE without Azure.
resource "azapi_resource" "rai_ungoverned" {
  count     = var.enable_ungoverned_model ? 1 : 0
  type      = "Microsoft.CognitiveServices/accounts/raiPolicies@2024-10-01"
  name      = "ungoverned"
  parent_id = azurerm_cognitive_account.ai.id

  body = {
    properties = {
      basePolicyName = "Microsoft.DefaultV2"
      mode           = "Default"
      contentFilters = [
        for entry in setproduct(["Hate", "Sexual", "Violence", "Selfharm"], ["Prompt", "Completion"]) : {
          name              = entry[0]
          blocking          = false
          enabled           = false
          severityThreshold = "High"
          source            = entry[1]
        }
      ]
    }
  }

  schema_validation_enabled = false
}

# --- Ungoverned deployment: attaches the filters-off policy ------------------
resource "azurerm_cognitive_deployment" "ungoverned" {
  count                = var.enable_ungoverned_model ? 1 : 0
  name                 = "gpt-ungoverned"
  cognitive_account_id = azurerm_cognitive_account.ai.id
  rai_policy_name      = azapi_resource.rai_ungoverned[0].name

  model {
    format  = "OpenAI"
    name    = var.ungoverned_model_name
    version = var.model_version
  }

  sku {
    name     = "GlobalStandard"
    capacity = var.model_deployment_capacity
  }
}

# --- Foundry project (the unit the SDK / Agent Service binds to) -------------
resource "azapi_resource" "project" {
  type      = "Microsoft.CognitiveServices/accounts/projects@2025-04-01-preview"
  name      = "proj-${local.base}"
  parent_id = azurerm_cognitive_account.ai.id
  location  = azurerm_resource_group.rg.location

  depends_on = [azapi_update_resource.ai_allow_projects]

  identity {
    type = "SystemAssigned"
  }

  body = {
    properties = {
      displayName = "Zava Wealth Advisor"
      description = "Damn Vulnerable Agentic App — security lab project."
    }
  }

  schema_validation_enabled = false
}

# Optional cohort sandbox mode: one Foundry project per lab user so participants
# can manipulate their own agents, prompts, and guardrails without stepping on
# each other. Default cohort deployments keep a single shared Foundry project and
# vary learner access through Entra groups, PostgreSQL rows, and AI Search ACLs.
resource "azapi_resource" "cohort_project" {
  for_each  = var.deploy_cohort_foundry_projects ? local.cohort_user_map : {}
  type      = "Microsoft.CognitiveServices/accounts/projects@2025-04-01-preview"
  name      = "proj-${local.base}-${each.value.compact_id}"
  parent_id = azurerm_cognitive_account.ai.id
  location  = azurerm_resource_group.rg.location

  depends_on = [azapi_update_resource.ai_allow_projects]

  identity {
    type = "SystemAssigned"
  }

  body = {
    properties = {
      displayName = "Zava Wealth Advisor - ${each.key}"
      description = "Per-user Foundry project for ${each.key}. Shares model deployments, AI Search, PostgreSQL, MCP, and APIM with the cohort."
    }
  }

  schema_validation_enabled = false
}

# Let the deployer create agents / call models via the SDK.
resource "azurerm_role_assignment" "ai_developer" {
  scope                = azurerm_cognitive_account.ai.id
  role_definition_name = "Azure AI Developer"
  principal_id         = data.azurerm_client_config.current.object_id
}
