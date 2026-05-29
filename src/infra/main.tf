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
