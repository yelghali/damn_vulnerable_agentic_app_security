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
  default     = "gpt-4o-mini"
  description = "Foundry model to deploy (governed + ungoverned variants)."
}

variable "model_version" {
  type        = string
  default     = "2024-07-18"
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
  default     = "Developer_1"
  description = "APIM SKU. Developer_1 supports GenAI token-limit policies for the lab. Use Consumption_0 for lowest cost (some policies differ)."
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
  default     = "gpt-4o-mini"
  description = "Model used for the V1 'ungoverned' deployment (content filters effectively disabled via a custom RAI policy)."
}

variable "enable_ungoverned_model" {
  type        = bool
  default     = false
  description = "Create the V1 'ungoverned' (filters-off) RAI policy + deployment. Requires an approved modified-content-filter exception on the subscription (aka.ms/oai/rai/exceptions); off by default so deploy succeeds on restricted/sponsored subscriptions. The V1 demo also works in OFFLINE_MODE."
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
