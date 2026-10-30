<#
.SYNOPSIS
    Gives each AI agent in config\agents.json its own identity in Microsoft Entra ID.

.DESCRIPTION
    Runs as the JML Engine app (app-only, certificate). The engine holds
    Application.ReadWrite.OwnedBy: it can create agent identities and manage the ones it
    created, and nothing else in the tenant. For each agent without an identity it:

      1. creates an app registration, "<NAME> (AI agent)", with the agent's PUBLIC certificate
         from jml\agents\<NAME>.cer. The private key never leaves the computer that runs the agent.
      2. creates the agent's service principal, tagged OrbitAgent and Sponsor:<employeeId>.
      3. confirms the engine can manage it, which it needs to suspend the agent later.
      4. writes appId and servicePrincipalId back to config\agents.json.

    It never grants an agent access to anything. A human admin grants each agent its
    Mission Control roles in the portal, so access always needs a person's approval.
    Safe to re-run: agents that already have an identity are skipped.

.EXAMPLE
    .\Register-OrbitAgents.ps1
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'config\settings.json'),
    [string]$AgentRegisterPath = (Join-Path $PSScriptRoot 'config\agents.json')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'JmlEngine.psm1') -Force
Import-Module Microsoft.Graph.Authentication

$settings = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json
Import-JmlAgentRegister -Path $AgentRegisterPath | Out-Null          # validates names and sponsors
$register = Get-Content -LiteralPath $AgentRegisterPath -Raw | ConvertFrom-Json

function Save-Register {
    $register | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $AgentRegisterPath -Encoding UTF8
}

function Invoke-Graph {
    param([string]$Method, [string]$Uri, $Body)
    $params = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject' }
    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 6 -Compress)
        $params.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @params
}

Connect-MgGraph -TenantId $settings.graph.tenantId -ClientId $settings.graph.clientId `
    -CertificateThumbprint $settings.graph.certificateThumbprint -NoWelcome
$unmanaged = @()
try {
    foreach ($agent in @($register.agents)) {
        $name = "$($agent.name)"
        if ($agent.servicePrincipalId) {
            try {
                Invoke-Graph GET "v1.0/servicePrincipals/$($agent.servicePrincipalId)?`$select=id" | Out-Null
                Write-Host ("exists   {0,-7} {1}" -f $name, $agent.appId) -ForegroundColor DarkGray
                continue
            }
            catch {
                Write-Warning "$name's recorded identity wasn't found in Entra ID; creating a new one."
                $agent.appId = $null
                $agent.servicePrincipalId = $null
            }
        }

        $cerPath = Join-Path $PSScriptRoot "agents\$name.cer"
        if (-not (Test-Path -LiteralPath $cerPath)) {
            Write-Warning "Skipping ${name}: no certificate at $cerPath. Run 'python agents\make_certs.py' on the computer that runs the agent and copy its .cer files here."
            continue
        }
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (Resolve-Path -LiteralPath $cerPath).Path
        $sponsor = "$($agent.sponsorEmployeeId)".Trim()
        $tags = @('OrbitAgent', "Sponsor:$sponsor")
        $notes = "AI agent at Meridian Orbital. $($agent.purpose) Sponsor: $sponsor. Created and governed by the JML Engine."
        if (-not $PSCmdlet.ShouldProcess("$name (AI agent)", 'Create agent identity')) { continue }

        $app = Invoke-Graph POST 'v1.0/applications' @{
            displayName    = "$name (AI agent)"
            signInAudience = 'AzureADMyOrg'
            notes          = $notes
            tags           = $tags
            keyCredentials = @(@{
                    type          = 'AsymmetricX509Cert'
                    usage         = 'Verify'
                    key           = [Convert]::ToBase64String($cert.RawData)
                    displayName   = $cert.Subject
                    startDateTime = $cert.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                    endDateTime   = $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                })
        }
        $sp = $null
        for ($attempt = 1; -not $sp; $attempt++) {     # a brand-new app can take a few seconds to replicate
            try { $sp = Invoke-Graph POST 'v1.0/servicePrincipals' @{ appId = $app.appId; tags = $tags; notes = $notes } }
            catch { if ($attempt -ge 6) { throw }; Start-Sleep -Seconds 5 }
        }
        $agent.appId = $app.appId
        $agent.servicePrincipalId = $sp.id
        Save-Register
        Write-Host ("created  {0,-7} {1}  sponsor {2}" -f $name, $app.appId, $sponsor) -ForegroundColor Green

        # The engine must be able to manage the agent, or it couldn't suspend it later.
        try { Invoke-Graph PATCH "v1.0/servicePrincipals/$($sp.id)" @{ notes = $notes } | Out-Null }
        catch { $unmanaged += $agent }
    }
}
finally {
    Disconnect-MgGraph | Out-Null
}

if ($unmanaged.Count -gt 0) {
    Write-Warning "The JML Engine can't manage: $(($unmanaged | ForEach-Object name) -join ', '). Make it an owner by running this as an admin:"
    Write-Host "  Connect-MgGraph -UseDeviceCode -Scopes Application.ReadWrite.All"
    Write-Host "  `$engine = Get-MgServicePrincipal -Filter `"appId eq '$($settings.graph.clientId)'`""
    foreach ($agent in $unmanaged) {
        Write-Host "  New-MgServicePrincipalOwnerByRef -ServicePrincipalId $($agent.servicePrincipalId) -BodyParameter @{ '@odata.id' = `"https://graph.microsoft.com/v1.0/directoryObjects/`$(`$engine.Id)`" }"
    }
}

Write-Host "`nNext: grant each agent its Mission Control roles in the portal (App registrations > <agent> > API permissions)," -ForegroundColor Cyan
Write-Host "then copy config\agents.json to the same folder on the computer that runs the agents." -ForegroundColor Cyan
