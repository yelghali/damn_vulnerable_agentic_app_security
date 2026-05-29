variable "prefix" {
  type        = string
  default     = "zava"
  description = "Short name prefix for all resources (lowercase, <= 10 chars)."
}

variable "location" {
  type        = string
  default     = "eastus2"
  description = "Azure region. Must have quota for the chosen model + PostgreSQL. Known-good: eastus2, swedencentral."
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
  description = "PostgreSQL administrator password. Provide via TF_VAR_pg_admin_password; never commit it."
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
