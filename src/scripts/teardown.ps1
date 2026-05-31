<#
.SYNOPSIS
  Tear down the Zava Wealth Advisor lab infrastructure.

.DESCRIPTION
  Wraps `terraform destroy` for src/infra so participants can cleanly remove
  every resource they provisioned. The lab uses only throwaway sample data, so
  destroying is always safe.

.PARAMETER Force
  Skip the interactive confirmation prompt (passes -auto-approve to Terraform).

.EXAMPLE
  ./src/scripts/teardown.ps1
  ./src/scripts/teardown.ps1 -Force
#>
[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$infraDir = Join-Path $repoRoot "src\infra"

Write-Host "==> Destroying lab infra in $infraDir"

Push-Location $infraDir
try {
    terraform init -input=false
    if ($Force) {
        terraform destroy -input=false -auto-approve
    }
    else {
        terraform destroy -input=false
    }
}
finally {
    Pop-Location
}

Write-Host "==> Teardown complete. Remember to set OFFLINE_MODE=true in .env to keep running locally."
