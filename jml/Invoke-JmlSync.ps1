<#
.SYNOPSIS
    HR-driven joiner / mover / leaver (JML) engine for Active Directory, with
    Microsoft Entra ID session revocation for leavers.

.DESCRIPTION
    1. Loads and validates the HR feed (the source of truth).
    2. Reads every account under the lab search base that carries an employeeID.
    3. Builds a plan: joiners, movers, rehires, leavers, deferred changes, orphans.
    4. Shows the plan and saves it to out\plan-<runId>.json.
    5. Only with -Apply: executes it, logging every change to logs\jml-<runId>.jsonl.

    Leaver order is deliberate: disable -> revoke Entra sessions -> reset password
    -> strip managed groups -> move to the Disabled OU. Disabling in AD reaches Entra
    only on the next sync cycle, and existing refresh tokens survive until revoked,
    so sessions are revoked directly through Microsoft Graph.

.PARAMETER HrFeed
    Path to the HR CSV export.
.PARAMETER Apply
    Execute the plan. Without it the run is a dry run and changes nothing.
.PARAMETER RevokeCloudSessions
    Connect to Microsoft Graph (app-only, certificate) and revoke leavers' sessions.
.PARAMETER Force
    Proceed even if the blast-radius guard trips. Review the saved plan first.
.PARAMETER ManageAgents
    Also apply the sponsor rule to the AI agents in config\agents.json: any agent whose human
    sponsor has left (or that has no sponsor) is suspended in Entra ID in the same run.
    Reads agent state from Microsoft Graph, so it connects to Graph even on a dry run.
.PARAMETER AsOf
    Date used for start/end-date decisions. Defaults to today.

.EXAMPLE
    .\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day1.csv
    Dry run: shows and saves the plan, changes nothing.

.EXAMPLE
    .\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day2.csv -Apply -RevokeCloudSessions

.EXAMPLE
    .\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day3.csv -Apply -RevokeCloudSessions -ManageAgents
    Day 3: a sponsor leaves, and the agent they sponsor is suspended in the same run.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HrFeed,
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'config\settings.json'),
    [string]$RoleMapPath = (Join-Path $PSScriptRoot 'config\role-map.json'),
    [switch]$Apply,
    [switch]$RevokeCloudSessions,
    [switch]$Force,
    [switch]$ManageAgents,
    [string]$AgentRegisterPath = (Join-Path $PSScriptRoot 'config\agents.json'),
    [datetime]$AsOf = (Get-Date).Date
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'JmlEngine.psm1') -Force

# ---------------------------------------------------------------------------
# Apply functions (use script-scope $settings, $groupDnByName, $graphConnected, $runId)
# ---------------------------------------------------------------------------

function Invoke-JmlJoiner {
    param([Parameter(Mandatory)]$Action)
    $attrs = $Action.Attributes
    $cn = [string]$attrs['DisplayName']
    $sameName = Get-ADObject -LDAPFilter "(name=$(ConvertTo-JmlLdapFilterValue -Value $cn))" `
        -SearchBase $Action.TargetOu -SearchScope OneLevel
    if ($sameName) { $cn = "$cn ($($Action.SamAccountName))" }

    $params = @{
        Name                  = $cn
        GivenName             = $attrs['GivenName']
        Surname               = $attrs['Surname']
        DisplayName           = $attrs['DisplayName']
        SamAccountName        = $Action.SamAccountName
        UserPrincipalName     = $Action.UserPrincipalName
        EmployeeID            = $Action.EmployeeId
        Department            = $attrs['Department']
        Title                 = $attrs['Title']
        Company               = $settings.company
        Description           = "Provisioned by JML run $runId"
        Path                  = $Action.TargetOu
        AccountPassword       = (New-JmlRandomPassword)
        ChangePasswordAtLogon = $true
        Enabled               = $true
    }
    New-ADUser @params
    Write-JmlLog -Event 'UserCreated' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName `
        -Detail "in $(Get-JmlDnLeafValue -DistinguishedName $Action.TargetOu)"

    foreach ($g in $Action.GroupsToAdd) {
        Add-ADGroupMember -Identity $groupDnByName[$g] -Members $Action.SamAccountName
        Write-JmlLog -Event 'GroupAdd' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName -Detail $g
    }
}

function Invoke-JmlUpdate {
    <# Movers and rehires. #>
    param([Parameter(Mandatory)]$Action)
    $id = $Action.ObjectGuid

    if ($Action.Attributes.Count -gt 0) {
        $set = @{}
        foreach ($k in $Action.Attributes.Keys) { $set[$k] = $Action.Attributes[$k] }
        Set-ADUser -Identity $id @set
        Write-JmlLog -Event 'AttributesUpdated' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName `
            -Detail (@($Action.Attributes.Keys) -join ',')
    }

    if ($Action.Action -eq 'Rehire') {
        Set-ADAccountPassword -Identity $id -Reset -NewPassword (New-JmlRandomPassword)
        Set-ADUser -Identity $id -ChangePasswordAtLogon $true -Description "Rehired by JML run $runId"
        Enable-ADAccount -Identity $id
        Write-JmlLog -Event 'UserEnabled' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName -Detail 'rehire'
    }

    foreach ($g in $Action.GroupsToRemove) {
        Remove-ADGroupMember -Identity $groupDnByName[$g] -Members $id -Confirm:$false
        Write-JmlLog -Event 'GroupRemove' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName -Detail $g
    }
    foreach ($g in $Action.GroupsToAdd) {
        Add-ADGroupMember -Identity $groupDnByName[$g] -Members $id
        Write-JmlLog -Event 'GroupAdd' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName -Detail $g
    }

    if ($Action.MoveOu) {
        Move-ADObject -Identity $id -TargetPath $Action.TargetOu
        Write-JmlLog -Event 'UserMoved' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName `
            -Detail (Get-JmlDnLeafValue -DistinguishedName $Action.TargetOu)
    }
}

function Invoke-JmlLeaver {
    param([Parameter(Mandatory)]$Action)
    $id = $Action.ObjectGuid

    Disable-ADAccount -Identity $id
    Write-JmlLog -Event 'UserDisabled' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName

    if ($graphConnected -and $RevokeCloudSessions) {
        try {
            Revoke-MgUserSignInSession -UserId $Action.UserPrincipalName | Out-Null
            Write-JmlLog -Event 'SessionsRevoked' -EmployeeId $Action.EmployeeId -Target $Action.UserPrincipalName
        }
        catch {
            Write-JmlLog -Level WARN -Event 'RevokeFailed' -EmployeeId $Action.EmployeeId `
                -Target $Action.UserPrincipalName -Detail $_.Exception.Message
        }
    }

    Set-ADAccountPassword -Identity $id -Reset -NewPassword (New-JmlRandomPassword)
    Set-ADUser -Identity $id -Description "Disabled by JML run $runId (HR termination)"

    foreach ($g in $Action.GroupsToRemove) {
        Remove-ADGroupMember -Identity $groupDnByName[$g] -Members $id -Confirm:$false
        Write-JmlLog -Event 'GroupRemove' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName -Detail $g
    }

    if ($Action.MoveOu) {
        Move-ADObject -Identity $id -TargetPath $Action.TargetOu
        Write-JmlLog -Event 'UserMoved' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName `
            -Detail (Get-JmlDnLeafValue -DistinguishedName $Action.TargetOu)
    }
}

function Set-JmlManager {
    param([Parameter(Mandatory)]$Action)
    $identity = if ($Action.ObjectGuid) { $Action.ObjectGuid } else { $Action.SamAccountName }
    if (-not $Action.ManagerId) {
        Set-ADUser -Identity $identity -Clear manager
        Write-JmlLog -Event 'ManagerCleared' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName
        return
    }
    $manager = Get-ADUser -LDAPFilter "(employeeID=$(ConvertTo-JmlLdapFilterValue -Value $Action.ManagerId))" `
        -SearchBase $settings.searchBase | Select-Object -First 1
    if (-not $manager) {
        Write-JmlLog -Level WARN -Event 'ManagerNotFound' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName `
            -Detail "No account with employeeID $($Action.ManagerId)"
        return
    }
    Set-ADUser -Identity $identity -Manager $manager.DistinguishedName
    Write-JmlLog -Event 'ManagerSet' -EmployeeId $Action.EmployeeId -Target $Action.SamAccountName `
        -Detail $manager.SamAccountName
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

$runId   = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Start-JmlLog -Directory (Join-Path $PSScriptRoot 'logs') -RunId $runId
$mode    = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
Write-JmlLog -Event 'RunStart' -Detail "mode=$mode feed=$(Split-Path $HrFeed -Leaf) asOf=$($AsOf.ToString('yyyy-MM-dd'))"

if (-not (Test-Path -LiteralPath $SettingsPath)) {
    throw "Settings not found: $SettingsPath. Copy config\settings.example.json to config\settings.json and edit it."
}
$settings = Get-Content -LiteralPath $SettingsPath -Raw | ConvertFrom-Json
$roleMap  = Get-Content -LiteralPath $RoleMapPath -Raw | ConvertFrom-Json
if ($settings.upnSuffix -like '*CHANGEME*') {
    throw "Set upnSuffix in $SettingsPath to your tenant domain (for example yourtenant.onmicrosoft.com)."
}

$hrRecords = @(Import-HrFeed -Path $HrFeed)
Write-JmlLog -Event 'FeedLoaded' -Detail "$($hrRecords.Count) HR records"

# --- Current state from AD ---------------------------------------------------
Import-Module ActiveDirectory
$dc = @((Get-ADDomainController -Discover -Service ADWS).HostName)[0]
$PSDefaultParameterValues['*-AD*:Server'] = $dc   # pin every AD call to one DC: no replication surprises mid-run

$groupDnByName = @{}
$groupNameByDn = @{}
foreach ($name in Get-JmlManagedGroupNames -RoleMap $roleMap) {
    $group = Get-ADGroup -LDAPFilter "(name=$(ConvertTo-JmlLdapFilterValue -Value $name))" -SearchBase $settings.groupsOu
    if (-not $group) { throw "Managed group '$name' not found under $($settings.groupsOu). Run Initialize-LabDirectory.ps1 first." }
    $groupDnByName[$name] = $group.DistinguishedName
    $groupNameByDn[$group.DistinguishedName] = $name
}

$adUsers = @(Get-ADUser -SearchBase $settings.searchBase -LDAPFilter '(employeeID=*)' `
        -Properties EmployeeID, DisplayName, Department, Title, Manager, MemberOf)
$employeeIdByDn = @{}
foreach ($u in $adUsers) { $employeeIdByDn[[string]$u.DistinguishedName] = [string]$u.EmployeeID }
$currentUsers = @($adUsers | ForEach-Object {
        ConvertTo-JmlCurrentUser -AdUser $_ -GroupNameByDn $groupNameByDn -EmployeeIdByDn $employeeIdByDn
    })
$enabledCount = @($currentUsers | Where-Object { $_.Enabled }).Count
$takenNames   = @(Get-ADUser -Filter * | ForEach-Object { $_.SamAccountName })
Write-JmlLog -Event 'StateLoaded' -Detail "$($currentUsers.Count) managed accounts ($enabledCount enabled) via $dc"

# --- Microsoft Graph (connected only when needed) ------------------------------
$graphConnected = $false
function Connect-JmlGraph {
    if ($script:graphConnected) { return }
    Import-Module Microsoft.Graph.Authentication
    Connect-MgGraph -TenantId $settings.graph.tenantId -ClientId $settings.graph.clientId `
        -CertificateThumbprint $settings.graph.certificateThumbprint -NoWelcome
    $script:graphConnected = $true
    Write-JmlLog -Event 'GraphConnected' -Detail "app-only, client $($settings.graph.clientId)"
}
function Disconnect-JmlGraph {
    if ($script:graphConnected) { Disconnect-MgGraph | Out-Null; $script:graphConnected = $false }
}

# --- Plan ----------------------------------------------------------------------
$plan = New-JmlPlan -HrRecords $hrRecords -CurrentUsers $currentUsers -RoleMap $roleMap -Settings $settings `
    -TakenSamAccountNames $takenNames -AsOf $AsOf

$agentPlan = $null
if ($ManageAgents) {
    $agents = @((Import-JmlAgentRegister -Path $AgentRegisterPath).agents)
    Connect-JmlGraph
    $agentState = @{}
    foreach ($agent in @($agents | Where-Object { $_.servicePrincipalId })) {
        $id = "$($agent.servicePrincipalId)"
        try {
            $sp = Invoke-MgGraphRequest -Method GET -OutputType PSObject `
                -Uri "v1.0/servicePrincipals/$($id)?`$select=id,displayName,accountEnabled"
            $agentState[$id] = @{ Found = $true; Enabled = [bool]$sp.accountEnabled }
        }
        catch {
            if ("$($_.Exception.Message)" -match 'NotFound|does not exist|Request_ResourceNotFound') {
                $agentState[$id] = @{ Found = $false; Enabled = $false }
            }
            else {
                Disconnect-JmlGraph
                throw "Can't read agent $($agent.name) in Entra ID: $($_.Exception.Message) " +
                "The JML Engine app needs Application.ReadWrite.OwnedBy and must own the agent; Register-OrbitAgents.ps1 sets both up."
            }
        }
    }
    $agentPlan = New-JmlAgentPlan -Agents $agents -CurrentState $agentState -HrRecords $hrRecords -AsOf $AsOf
    $plan | Add-Member -NotePropertyName AgentPlan -NotePropertyValue $agentPlan
}

$outDir = Join-Path $PSScriptRoot 'out'
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$planFile = Join-Path $outDir "plan-$runId.json"
$plan | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $planFile -Encoding UTF8
Show-JmlPlan -Plan $plan
if ($agentPlan) { Show-JmlAgentPlan -AgentPlan $agentPlan }
Write-JmlLog -Event 'PlanSaved' -Detail $planFile

$safety = Test-JmlPlanSafety -Plan $plan -EnabledUserCount $enabledCount -MaxPercent ([double]$settings.maxLeaverPercent)
foreach ($reason in $safety.Reasons) { Write-JmlLog -Level WARN -Event 'SafetyGuard' -Detail $reason }

if (-not $Apply) {
    Disconnect-JmlGraph
    Write-JmlLog -Event 'RunEnd' -Detail 'Dry run only; nothing changed. Re-run with -Apply to execute.'
    exit 0
}
if (-not $safety.Passed -and -not $Force) {
    Disconnect-JmlGraph
    Write-JmlLog -Level ERROR -Event 'RunAborted' -Detail 'Safety guard tripped. Review the plan; re-run with -Force only if it is correct.'
    exit 2
}

$leaverCount = @($plan.Actions | Where-Object { $_.Action -eq 'Leaver' }).Count
if ($leaverCount -gt 0 -and -not $RevokeCloudSessions) {
    Write-JmlLog -Level WARN -Event 'NoCloudRevoke' `
        -Detail 'Leavers present without -RevokeCloudSessions: Entra refresh tokens stay valid until they expire or are revoked.'
}

$failures = 0
try {
    if ($RevokeCloudSessions -and $leaverCount -gt 0) {
        Import-Module Microsoft.Graph.Users.Actions
        Connect-JmlGraph
    }

    $managerQueue = New-Object System.Collections.Generic.List[object]
    foreach ($kind in 'Leaver', 'Joiner', 'Rehire', 'Mover') {
        foreach ($action in @($plan.Actions | Where-Object { $_.Action -eq $kind })) {
            try {
                if ($kind -eq 'Leaver') { Invoke-JmlLeaver -Action $action }
                elseif ($kind -eq 'Joiner') { Invoke-JmlJoiner -Action $action }
                else { Invoke-JmlUpdate -Action $action }
                if ($action.SetManager) { $managerQueue.Add($action) }
            }
            catch {
                $failures++
                Write-JmlLog -Level ERROR -Event "${kind}Failed" -EmployeeId $action.EmployeeId `
                    -Target $action.SamAccountName -Detail $_.Exception.Message
            }
        }
    }

    # Managers last, so a manager hired in this same run already exists.
    foreach ($action in $managerQueue) {
        try { Set-JmlManager -Action $action }
        catch {
            $failures++
            Write-JmlLog -Level ERROR -Event 'ManagerFailed' -EmployeeId $action.EmployeeId `
                -Target $action.SamAccountName -Detail $_.Exception.Message
        }
    }

    # Agents: suspend every agent whose sponsor is gone. Disabling the service principal stops
    # new tokens; Mission Control checks agent status live, so existing tokens stop working too.
    if ($agentPlan) {
        foreach ($action in @($agentPlan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' })) {
            try {
                $body = @{ accountEnabled = $false; notes = $action.Note } | ConvertTo-Json -Compress
                Invoke-MgGraphRequest -Method PATCH -Uri "v1.0/servicePrincipals/$($action.ServicePrincipalId)" `
                    -Body $body -ContentType 'application/json' | Out-Null
                Write-JmlLog -Event 'AgentSuspended' -Target $action.Agent -Detail $action.Reason
            }
            catch {
                $failures++
                Write-JmlLog -Level ERROR -Event 'AgentSuspendFailed' -Target $action.Agent -Detail $_.Exception.Message
            }
        }
        foreach ($action in @($agentPlan.Actions | Where-Object { $_.Action -ne 'AgentSuspend' })) {
            Write-JmlLog -Level WARN -Event $action.Action -Target $action.Agent -Detail $action.Reason
        }
    }
}
finally {
    Disconnect-JmlGraph
}

$summaryText = @($plan.Summary.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' '
if ($agentPlan) {
    $summaryText += ' ' + (@($agentPlan.Summary.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')
}
if ($failures -gt 0) {
    Write-JmlLog -Level ERROR -Event 'RunEnd' -Detail "$failures action(s) failed. $summaryText. Log: $logFile"
    exit 1
}
Write-JmlLog -Event 'RunEnd' -Detail "Applied. $summaryText. Log: $logFile"
exit 0
