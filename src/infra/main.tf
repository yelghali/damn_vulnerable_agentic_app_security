# ---------------------------------------------------------------------------
# Core: resource group, naming, and a random suffix for globally-unique names.
# ---------------------------------------------------------------------------

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
  numeric = true
}

locals {
  # Lowercased, suffixed base name used across resources.
  base = "${var.prefix}${random_string.suffix.result}"

  deploy_container_apps = var.deploy_mcp_toolbox || var.deploy_app

  cohort_user_ids = var.enable_cohort_mode ? [
    for i in range(1, var.cohort_user_count + 1) : "${var.cohort_user_prefix}_${i}"
  ] : []

  cohort_user_map = {
    for user_id in local.cohort_user_ids : user_id => {
      safe_id       = replace(user_id, "_", "-")
      compact_id    = replace(user_id, "_", "")
      customer_id   = "CUST-${1000 + index(local.cohort_user_ids, user_id) + 1}"
      retail_group  = "zava-${user_id}-retail"
      private_group = "zava-${user_id}-private"
    }
  }

  # Public network access mirrors the security posture: open in the vulnerable
  # baseline (V7), locked down in secure mode.
  public_network_access = var.secure_mode ? false : true

  tags = var.tags
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-${local.base}"
  location = var.location
  tags     = local.tags
}
