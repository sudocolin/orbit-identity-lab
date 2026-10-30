<#
.SYNOPSIS
    One-time bootstrap: creates the lab OU tree and every group the JML engine manages,
    and optionally adds the tenant's domain as a UPN suffix. Safe to re-run.

.EXAMPLE
    .\Initialize-LabDirectory.ps1 -AddUpnSuffix
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'config\settings.json'),
    [string]$RoleMapPath = (Join-Path $PSScriptRoot 'config\role-map.json'),
    [switch]$AddUpnSuffix
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Import-Module (Join-Path $PSScriptRoot 'JmlEngine.psm1') -Force

$settings = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json
$roleMap  = Get-Content -LiteralPath $RoleMapPath -Raw | ConvertFrom-Json

function New-OuIfMissing {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    try {
        Get-ADOrganizationalUnit -Identity $DistinguishedName | Out-Null
        Write-Host "exists   $DistinguishedName" -ForegroundColor DarkGray
    }
    catch {
        $name   = Get-JmlDnLeafValue -DistinguishedName $DistinguishedName
        $parent = Get-JmlDnParent -DistinguishedName $DistinguishedName
        if ($PSCmdlet.ShouldProcess($DistinguishedName, 'Create OU')) {
            New-ADOrganizationalUnit -Name $name -Path $parent -ProtectedFromAccidentalDeletion $true
            Write-Host "created  $DistinguishedName" -ForegroundColor Green
        }
    }
}

# OU tree: parents first
New-OuIfMissing -DistinguishedName $settings.searchBase
foreach ($ou in $settings.usersOu, $settings.disabledOu, $settings.groupsOu) { New-OuIfMissing -DistinguishedName $ou }
foreach ($prop in $roleMap.departments.PSObject.Properties) {
    $record = [pscustomobject]@{ Department = $prop.Name }
    New-OuIfMissing -DistinguishedName (Get-JmlDesiredOu -Record $record -RoleMap $roleMap -Settings $settings)
}

# Managed groups
foreach ($name in Get-JmlManagedGroupNames -RoleMap $roleMap) {
    $existing = Get-ADGroup -LDAPFilter "(name=$(ConvertTo-JmlLdapFilterValue -Value $name))" -SearchBase $settings.groupsOu
    if ($existing) { Write-Host "exists   group $name" -ForegroundColor DarkGray; continue }
    if ($PSCmdlet.ShouldProcess($name, 'Create security group')) {
        New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security `
            -Path $settings.groupsOu -Description 'Managed by the JML engine (role-map.json). Do not edit membership by hand.'
        Write-Host "created  group $name" -ForegroundColor Green
    }
}

# UPN suffix so synced users sign in to Entra as user@<tenant domain>
if ($AddUpnSuffix) {
    $forest = Get-ADForest
    if (@($forest.UPNSuffixes) -contains $settings.upnSuffix) {
        Write-Host "exists   UPN suffix $($settings.upnSuffix)" -ForegroundColor DarkGray
    }
    elseif ($PSCmdlet.ShouldProcess($settings.upnSuffix, 'Add forest UPN suffix')) {
        Set-ADForest -Identity $forest -UPNSuffixes @{ Add = $settings.upnSuffix }
        Write-Host "added    UPN suffix $($settings.upnSuffix)" -ForegroundColor Green
    }
}

Write-Host "`nDone. Next: .\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day1.csv" -ForegroundColor Cyan
