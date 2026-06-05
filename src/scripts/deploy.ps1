<#
.SYNOPSIS
  Deploy the Zava Wealth Advisor lab infrastructure and emit .env values.

.DESCRIPTION
  Wraps `terraform apply` for src/infra and maps the non-secret Terraform
  outputs to the environment variables the app expects (see .env.example).
  Secrets (model/search keys, Postgres connection strings) are kept in Key
  Vault by the infra and are NOT written to disk by this script — pull them
  with `az keyvault secret show` or a managed identity at runtime.

  This is a convenience wrapper for the workshop's Module 0/1 deploy step.
  Re-runnable: Terraform state makes `apply` idempotent.

.PARAMETER SecureMode
  Apply the infra with var.secure_mode=true (the hardened end-state). Defaults
  to $false so Module 0 stands up the vulnerable baseline.

.PARAMETER DeployApim
  Provision the APIM AI gateway (var.deploy_apim=true). Off by default because
  APIM provisioning is slow; turn it on for Module 6.

.PARAMETER DeployApp
  Deploy the FastAPI lab app to Azure Container Apps for browser-only learners.

.PARAMETER AppImage
  Container image to run when -DeployApp is used, e.g. myacr.azurecr.io/zava-lab:latest.

.PARAMETER AppRegistryServer
  Optional private registry server, e.g. myacr.azurecr.io. Leave blank for public images.

.PARAMETER EnvFile
  Path to the .env file to update. Defaults to ./.env at the repo root.

.EXAMPLE
  ./src/scripts/deploy.ps1
  ./src/scripts/deploy.ps1 -SecureMode -DeployApim
#>
[CmdletBinding()]
param(
    [switch]$SecureMode,
    [switch]$DeployApim,
    [switch]$DeployApp,
    [string]$AppImage,
    [string]$AppRegistryServer,
    [string]$AppRegistryUsername,
    [string]$AppRegistryPassword,
    [switch]$AppAzureMode,
    [string]$EnvFile
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$infraDir = Join-Path $repoRoot "src\infra"
if (-not $EnvFile) { $EnvFile = Join-Path $repoRoot ".env" }

Write-Host "==> Repo root : $repoRoot"
Write-Host "==> Infra dir : $infraDir"
Write-Host "==> Env file  : $EnvFile"
Write-Host "==> secure_mode=$([bool]$SecureMode) deploy_apim=$([bool]$DeployApim) deploy_app=$([bool]$DeployApp)"

if ($DeployApp -and -not $AppImage) {
  throw "-AppImage is required with -DeployApp. Build/push the Dockerfile first, then pass the image name."
}

# --- Terraform apply --------------------------------------------------------
Push-Location $infraDir
try {
    terraform init -input=false
    terraform apply -input=false -auto-approve `
        -var ("secure_mode=" + $SecureMode.ToString().ToLower()) `
        -var ("deploy_apim=" + $DeployApim.ToString().ToLower()) `
        -var ("deploy_app=" + $DeployApp.ToString().ToLower()) `
        -var ("app_offline_mode=" + (-not $AppAzureMode).ToString().ToLower()) `
        -var ("app_container_image=" + $AppImage) `
        -var ("app_registry_server=" + $AppRegistryServer) `
        -var ("app_registry_username=" + $AppRegistryUsername) `
        -var ("app_registry_password=" + $AppRegistryPassword)

    $tf = terraform output -json | ConvertFrom-Json
}
finally {
    Pop-Location
}

function Get-Out([string]$name) {
    if ($tf.PSObject.Properties.Name -contains $name) { return $tf.$name.value }
    return ""
}

$foundryEndpoint = Get-Out "foundry_endpoint"
$foundryProject  = Get-Out "foundry_project_name"
$projectEndpoint = if ($foundryEndpoint -and $foundryProject) {
    ($foundryEndpoint.TrimEnd("/")) + "/api/projects/" + $foundryProject
} else { "" }

# Map non-secret outputs -> .env keys. Secrets stay in Key Vault.
$map = [ordered]@{
    "OFFLINE_MODE"                  = "false"
    "SECURE_MODE"                   = $SecureMode.ToString().ToLower()
    "FOUNDRY_PROJECT_ENDPOINT"      = $projectEndpoint
    "FOUNDRY_MODEL_DEPLOYMENT"      = Get-Out "model_deployment_governed"
    "FOUNDRY_UNGOVERNED_DEPLOYMENT" = Get-Out "model_deployment_ungoverned"
    "SEARCH_ENDPOINT"               = Get-Out "search_endpoint"
    "AI_GATEWAY_URL"                = Get-Out "ai_gateway_url"
    "KEY_VAULT_URI"                 = $(
        $kv = Get-Out "key_vault_name"
        if ($kv) { "https://$kv.vault.azure.net/" } else { "" }
    )
    "PG_MCP_SERVER_URL"             = Get-Out "pg_mcp_server_url"
    "APP_URL"                       = Get-Out "app_url"
}

# --- Merge into .env (preserve existing keys, append/replace mapped ones) ----
$existing = @{}
if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*([A-Z0-9_]+)\s*=(.*)$') { $existing[$Matches[1]] = $Matches[2] }
    }
}
foreach ($k in $map.Keys) {
    if ($map[$k]) { $existing[$k] = $map[$k] }
}

$lines = $existing.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }
Set-Content -Path $EnvFile -Value $lines -Encoding UTF8

Write-Host ""
Write-Host "==> Wrote $($map.Keys.Count) infra values to $EnvFile"
Write-Host "==> Secrets remain in Key Vault: $(Get-Out 'key_vault_name')"
Write-Host "==> Next: 'python -m src.scripts.seed' then 'uvicorn src.app.main:app'"
