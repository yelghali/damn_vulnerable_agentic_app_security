variable "prefix" {
  type        = string
  default     = "zava"
  description = "Short name prefix for all resources (lowercase, <= 10 chars)."
}

variable "location" {
  type        = string
  default     = "swedencentral"
  description = "Azure region. Must have quota for the chosen model + PostgreSQL. Known-good: swedencentral, westus3. Note: eastus2 is offer-restricted for PostgreSQL on some subscriptions."
}

variable "model_name" {
  type        = string
  default     = "gpt-4.1-mini"
  description = "Foundry model to deploy (governed + ungoverned variants)."
}

variable "model_version" {
  type        = string
  default     = "2025-04-14"
  description = "Model version for the deployment."
}

variable "pg_admin_user" {
  type        = string
  default     = "zavaadmin"
  description = "PostgreSQL administrator login."
}

variable "pg_admin_password" {
  type        = string
  sensitive   = true
  description = "PostgreSQL administrator password. Provide via TF_VAR_pg_admin_password or terraform.tfvars; never commit it."
}

variable "entra_admin_object_id" {
  type        = string
  default     = ""
  description = "Microsoft Entra object ID to set as the PostgreSQL Entra administrator. Empty = use the deploying identity (azurerm_client_config)."
}

variable "entra_admin_principal_name" {
  type        = string
  default     = ""
  description = "Principal name (UPN) shown for the PostgreSQL Entra administrator. Should match the entra_admin_object_id identity."
}

variable "tags" {
  type = map(string)
  default = {
    project = "zava-wealth-advisor-lab"
    purpose = "security-lab"
    warning = "intentionally-vulnerable-sample-data-only"
  }
}

# ---------------------------------------------------------------------------
# Security posture — the single lever that flips the infra from the vulnerable
# baseline (Module 0) toward the hardened end state. Individual modules toggle
# the matching app-level ENABLE_* flags in src/config.py; this variable drives
# the *infrastructure* controls (network exposure, V7).
# ---------------------------------------------------------------------------
variable "secure_mode" {
  type        = bool
  default     = false
  description = "false = vulnerable baseline (public network access on data + AI services). true = hardened (public access disabled; pair with private endpoints / VNet in Module 6)."
}

variable "deploy_apim" {
  type        = bool
  default     = false
  description = "Deploy the Azure API Management AI Gateway (V10, Module 6). Off by default because the Developer SKU takes ~30-45 min to provision and is billable; enable it when you reach Module 6."
}

variable "apim_sku" {
  type        = string
  default     = "StandardV2_1"
  description = "APIM SKU. StandardV2_1 provisions faster for classroom cohorts; override to Developer_1 or another supported SKU if your subscription requires it."
}

variable "apim_publisher_name" {
  type        = string
  default     = "Zava Wealth Advisor Lab"
  description = "APIM publisher display name (required by the service)."
}

variable "apim_publisher_email" {
  type        = string
  default     = "lab@example.com"
  description = "APIM publisher contact email (required by the service)."
}

variable "ai_gateway_tpm" {
  type        = number
  default     = 20000
  description = "Tokens-per-minute cap enforced by the APIM AI Gateway (V10 token-based rate limiting)."
}

variable "enable_cohort_mode" {
  type        = bool
  default     = false
  description = "Create a multi-user workshop cohort: per-user Foundry projects, optional per-user hosted apps, and per-user APIs on the shared APIM gateway. Shared AI Search, PostgreSQL, MCP, Key Vault, and monitoring stay singletons."
}

variable "cohort_user_count" {
  type        = number
  default     = 2
  description = "Number of generated lab users when enable_cohort_mode=true. Defaults to 2 for fast testing; can scale to 60/100 for large sessions."

  validation {
    condition     = var.cohort_user_count >= 1 && var.cohort_user_count <= 100
    error_message = "cohort_user_count must be between 1 and 100."
  }
}

variable "cohort_user_prefix" {
  type        = string
  default     = "user"
  description = "Prefix for generated lab users. User IDs become user_1, user_2, ... by default."
}

variable "deploy_cohort_apps" {
  type        = bool
  default     = false
  description = "When true with deploy_app=true and enable_cohort_mode=true, deploy one Zava Container App per generated lab user so each app points at that user's Foundry project while sharing Search/Postgres/MCP/APIM."
}

variable "pg_sku_name" {
  type        = string
  default     = "B_Standard_B1ms"
  description = "PostgreSQL Flexible Server compute SKU. Burstable B1ms keeps the lab cheap."
}

variable "search_sku" {
  type        = string
  default     = "basic"
  description = "Azure AI Search SKU. 'basic' supports vector search for the RAG index."
}

variable "ungoverned_model_name" {
  type        = string
  default     = "gpt-4.1-mini"
  description = "Model used for the V1 'ungoverned' deployment (content filters effectively disabled via a custom RAI policy)."
}

variable "enable_ungoverned_model" {
  type        = bool
  default     = false
  description = "Create the V1 'ungoverned' (filters-off) RAI policy + deployment. Requires an approved modified-content-filter exception on the subscription (aka.ms/oai/rai/exceptions); off by default so deploy succeeds on restricted/sponsored subscriptions. The V1 demo also works in OFFLINE_MODE."
}

variable "content_filter_severity_threshold" {
  type        = string
  default     = "Low"
  description = "Severity at which the GOVERNED deployment's harmful-content filters block (Low|Medium|High). 'Low' = strictest. This is the server-side Foundry guardrail (Module 1/2) provisioned declaratively as an RAI policy — not application code."

  validation {
    condition     = contains(["Low", "Medium", "High"], var.content_filter_severity_threshold)
    error_message = "content_filter_severity_threshold must be one of Low, Medium, High."
  }
}

# ---------------------------------------------------------------------------
# Azure MCP Server (Microsoft) — remote PostgreSQL MCP endpoint for Foundry
# agents, hosted on Azure Container Apps (see containerapp.tf).
# ---------------------------------------------------------------------------
variable "deploy_mcp_toolbox" {
  type        = bool
  default     = true
  description = "Deploy the Microsoft Azure MCP Server on Azure Container Apps as the remote PostgreSQL MCP endpoint that Foundry agents attach as their 'database' tool. One small always-on ACA replica; set false to skip it."
}

variable "mcp_toolbox_image" {
  type        = string
  default     = "mcr.microsoft.com/azure-sdk/azure-mcp:latest"
  description = "Container image for the remote MCP server. Defaults to the Microsoft-published Azure MCP Server image."
}

# ---------------------------------------------------------------------------
# Browser-accessible app deployment (for participants without local machines).
# Build/push the Dockerfile to your registry, then pass the image here.
# ---------------------------------------------------------------------------
variable "deploy_app" {
  type        = bool
  default     = false
  description = "Deploy the Zava FastAPI chat app to Azure Container Apps so participants can use the vulnerable app from a browser. Requires app_container_image."
}

variable "app_container_image" {
  type        = string
  default     = ""
  description = "Container image for the Zava FastAPI app, e.g. <acr>.azurecr.io/zava-lab:latest. Required when deploy_app=true."
}

variable "app_offline_mode" {
  type        = bool
  default     = true
  description = "true = browser-accessible vulnerable baseline with container-local SQLite/stub fallback. false = app calls Azure Foundry/PostgreSQL/MCP/APIM using the env below."
}

variable "vulnerable_app_url" {
  type        = string
  default     = ""
  description = "Optional URL for the vulnerable app variant. Surfaced in the UI mode switch for browser-only learners."
}

variable "secure_app_url" {
  type        = string
  default     = ""
  description = "Optional URL for the secure app variant. Surfaced in the UI mode switch for browser-only learners."
}

variable "pg_app_user" {
  type        = string
  default     = "zava_app_ro"
  description = "Least-privilege PostgreSQL role username used by the hosted app in secure mode. The seed script creates/grants this role."
}

variable "pg_app_password" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Password for pg_app_user. Required only when app_offline_mode=false and the hosted app needs PG_APP_CONNECTION."
}

variable "app_registry_server" {
  type        = string
  default     = ""
  description = "Optional private registry server for app_container_image, e.g. myacr.azurecr.io. Leave blank for public images."
}

variable "app_registry_username" {
  type        = string
  default     = ""
  description = "Optional private registry username."
}

variable "app_registry_password" {
  type        = string
  default     = ""
  sensitive   = true
  description = "Optional private registry password."
}
