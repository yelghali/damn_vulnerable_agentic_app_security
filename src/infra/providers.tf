terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      # Lab convenience only: lets `terraform destroy` fully clean up. Do NOT
      # use in production — disables soft-delete recovery.
      purge_soft_delete_on_destroy = true
    }
  }
}

provider "azapi" {}

# Identity Terraform is running as — used for Key Vault / RBAC assignments.
data "azurerm_client_config" "current" {}
