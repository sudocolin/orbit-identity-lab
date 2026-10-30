#Requires -Version 5.1
<#
    JmlEngine.psm1 - planning logic for the HR-driven joiner / mover / leaver engine.

    Everything in this module is side-effect free (no Active Directory or Graph calls),
    so the planner can be unit-tested on any machine. Invoke-JmlSync.ps1 reads AD,
    asks this module for a plan, and only then applies it.
#>
Set-StrictMode -Version Latest

$script:RequiredColumns   = @('EmployeeId', 'FirstName', 'LastName', 'Department', 'Title', 'ManagerId', 'Status', 'StartDate', 'EndDate')
$script:ValidStatuses     = @('Active', 'Terminated')
$script:EmployeeIdPattern = '^[A-Za-z0-9-]{1,32}$'   # also blocks LDAP/filter injection from the HR feed
$script:ActionOrder       = @('Error', 'Leaver', 'Joiner', 'Rehire', 'Mover', 'Deferred', 'Orphan')
$script:LogPath           = $null
$script:RunId             = ''

# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

function ConvertTo-JmlDate {
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact($Value.Trim(), 'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)
    if (-not $ok) { throw "Invalid date '$Value' (expected yyyy-MM-dd)" }
    return $parsed.Date
}

function Import-HrFeed {
    <#
    .SYNOPSIS
        Loads and validates the HR feed. Fails loudly on anything malformed rather
        than guessing, because a bad feed must never turn into bad access.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { throw "HR feed not found: $Path" }
    $rows = @(Import-Csv -LiteralPath $Path -Encoding UTF8)
    if ($rows.Count -eq 0) { throw "HR feed is empty: $Path" }

    $columns = @($rows[0].PSObject.Properties.Name)
    $missing = @($script:RequiredColumns | Where-Object { $columns -notcontains $_ })
    if ($missing.Count -gt 0) { throw "HR feed is missing columns: $($missing -join ', ')" }

    $seen = @{}
    foreach ($row in $rows) {
        $id = "$($row.EmployeeId)".Trim()
        if ($id -notmatch $script:EmployeeIdPattern) {
            throw "Invalid EmployeeId '$id' (letters, digits and hyphens only, max 32 characters)"
        }
        if ($seen.ContainsKey($id)) { throw "Duplicate EmployeeId in HR feed: $id" }
        $seen[$id] = $true

        $managerId = "$($row.ManagerId)".Trim()
        if ($managerId -and $managerId -notmatch $script:EmployeeIdPattern) {
            throw "Invalid ManagerId '$managerId' for EmployeeId $id"
        }

        $statusText = "$($row.Status)".Trim()
        $status = @($script:ValidStatuses | Where-Object { $_ -eq $statusText })
        if ($status.Count -ne 1) { throw "Invalid Status '$statusText' for EmployeeId $id (expected Active or Terminated)" }

        foreach ($field in 'FirstName', 'LastName', 'Department', 'Title') {
            if ([string]::IsNullOrWhiteSpace("$($row.$field)")) { throw "Empty $field for EmployeeId $id" }
        }

        [pscustomobject]@{
            EmployeeId = $id
            FirstName  = "$($row.FirstName)".Trim()
            LastName   = "$($row.LastName)".Trim()
            Department = "$($row.Department)".Trim()
            Title      = "$($row.Title)".Trim()
            ManagerId  = $managerId
            Status     = $status[0]
            StartDate  = ConvertTo-JmlDate -Value $row.StartDate
            EndDate    = ConvertTo-JmlDate -Value $row.EndDate
        }
    }
}

# ---------------------------------------------------------------------------
# Role model
# ---------------------------------------------------------------------------

function Get-JmlDepartmentRule {
    param([Parameter(Mandatory)]$RoleMap, [Parameter(Mandatory)][string]$Department)
    $prop = $RoleMap.departments.PSObject.Properties | Where-Object { $_.Name -eq $Department } | Select-Object -First 1
    if ($prop) { return $prop.Value }
    return $null
}

function Get-JmlManagedGroupNames {
    <# Every group the engine owns. Memberships in any other group are never read or changed. #>
    param([Parameter(Mandatory)]$RoleMap)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($g in @($RoleMap.baseline)) { $names.Add([string]$g) }
    foreach ($p in $RoleMap.departments.PSObject.Properties) {
        foreach ($g in @($p.Value.groups)) { $names.Add([string]$g) }
    }
    foreach ($rule in @($RoleMap.titleRules)) {
        foreach ($g in @($rule.groups)) { $names.Add([string]$g) }
    }
    return @($names | Sort-Object -Unique)
}

function Get-JmlDesiredGroups {
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$RoleMap)
    $groups = New-Object System.Collections.Generic.List[string]
    foreach ($g in @($RoleMap.baseline)) { $groups.Add([string]$g) }

    $dept = Get-JmlDepartmentRule -RoleMap $RoleMap -Department $Record.Department
    if ($dept) { foreach ($g in @($dept.groups)) { $groups.Add([string]$g) } }

    foreach ($rule in @($RoleMap.titleRules)) {
        if ($Record.Title -notmatch $rule.match) { continue }
        $hasDeptFilter = @($rule.PSObject.Properties.Name) -contains 'departments'
        if ($hasDeptFilter -and (@($rule.departments) -notcontains $Record.Department)) { continue }
        foreach ($g in @($rule.groups)) { $groups.Add([string]$g) }
    }
    return @($groups | Sort-Object -Unique)
}

# ---------------------------------------------------------------------------
# DN / naming helpers
# ---------------------------------------------------------------------------

function ConvertTo-JmlDnValue {
    param([Parameter(Mandatory)][string]$Value)
    $escaped = $Value -replace '([,+"\\<>;=])', '\$1'
    if ($escaped -match '^[ #]') { $escaped = '\' + $escaped }
    if ($escaped -match ' $') { $escaped = $escaped.Substring(0, $escaped.Length - 1) + '\ ' }
    return $escaped
}

function ConvertTo-JmlLdapFilterValue {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    return ($Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace "`0", '\00')
}

function Get-JmlDnParent {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    if ($DistinguishedName -match '^(?:[^,\\]|\\.)+,(.+)$') { return $Matches[1] }
    throw "Cannot parse DN: $DistinguishedName"
}

function Get-JmlDnLeafValue {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    if ($DistinguishedName -match '^[A-Za-z]+=((?:[^,\\]|\\.)+)(,|$)') { return ($Matches[1] -replace '\\(.)', '$1') }
    throw "Cannot parse DN: $DistinguishedName"
}

function Get-JmlDesiredOu {
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)]$RoleMap, [Parameter(Mandatory)]$Settings)
    $ouName = $Record.Department
    $dept = Get-JmlDepartmentRule -RoleMap $RoleMap -Department $Record.Department
    if ($dept -and (@($dept.PSObject.Properties.Name) -contains 'ou') -and $dept.ou) { $ouName = [string]$dept.ou }
    return "OU=$(ConvertTo-JmlDnValue -Value $ouName),$($Settings.usersOu)"
}

function New-JmlSamAccountName {
    <# first initial + last name, accents and punctuation stripped, numbered on collision. #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$FirstName,
        [Parameter(Mandatory)][string]$LastName,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Taken
    )
    $clean = {
        param([string]$s)
        $noAccents = $s.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', ''
        ($noAccents -replace '[^A-Za-z]', '').ToLowerInvariant()
    }
    $first = & $clean $FirstName
    $last  = & $clean $LastName
    if (-not $last) { throw "Cannot build an account name from last name '$LastName'" }

    $base = $last
    if ($first) { $base = $first.Substring(0, 1) + $last }
    if ($base.Length -gt 18) { $base = $base.Substring(0, 18) }   # sAMAccountName max is 20

    $candidate = $base
    $n = 1
    while ($Taken.Contains($candidate)) { $n++; $candidate = "$base$n" }
    [void]$Taken.Add($candidate)
    return $candidate
}

function New-JmlRandomPassword {
    <#
        Cryptographically random password returned as a SecureString. It is never shown
        or logged: joiners onboard with a Temporary Access Pass and register a passkey,
        so nobody ever needs to know this value.
    #>
    [OutputType([System.Security.SecureString])]
    param([ValidateRange(16, 128)][int]$Length = 24)

    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_=+?'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        while ($true) {
            $bytes = New-Object byte[] ($Length * 4)
            $rng.GetBytes($bytes)
            $chars = New-Object char[] $Length
            $upper = $false; $lower = $false; $digit = $false; $symbol = $false
            for ($i = 0; $i -lt $Length; $i++) {
                $c = $alphabet[[int]([BitConverter]::ToUInt32($bytes, $i * 4) % [uint32]$alphabet.Length)]
                $chars[$i] = $c
                if ([char]::IsUpper($c)) { $upper = $true }
                elseif ([char]::IsLower($c)) { $lower = $true }
                elseif ([char]::IsDigit($c)) { $digit = $true }
                else { $symbol = $true }
            }
            if ($upper -and $lower -and $digit -and $symbol) {
                $secure = New-Object System.Security.SecureString
                foreach ($c in $chars) { $secure.AppendChar($c) }
                [Array]::Clear($chars, 0, $chars.Length)
                $secure.MakeReadOnly()
                return $secure
            }
            [Array]::Clear($chars, 0, $chars.Length)
        }
    }
    finally { $rng.Dispose() }
}

# ---------------------------------------------------------------------------
# Current state
# ---------------------------------------------------------------------------

function ConvertTo-JmlCurrentUser {
    <# Normalizes an ADUser into the shape the planner expects. #>
    param(
        [Parameter(Mandatory)]$AdUser,
        [Parameter(Mandatory)][hashtable]$GroupNameByDn,
        [Parameter(Mandatory)][hashtable]$EmployeeIdByDn
    )
    $managed = @(@(foreach ($dn in @($AdUser.MemberOf)) {
                if ($dn -and $GroupNameByDn.ContainsKey([string]$dn)) { $GroupNameByDn[[string]$dn] }
            }) | Sort-Object)

    $managerId = ''
    if ($AdUser.Manager -and $EmployeeIdByDn.ContainsKey([string]$AdUser.Manager)) {
        $managerId = [string]$EmployeeIdByDn[[string]$AdUser.Manager]
    }

    [pscustomobject]@{
        EmployeeId        = [string]$AdUser.EmployeeID
        SamAccountName    = [string]$AdUser.SamAccountName
        UserPrincipalName = [string]$AdUser.UserPrincipalName
        ObjectGuid        = [string]$AdUser.ObjectGUID
        DistinguishedName = [string]$AdUser.DistinguishedName
        ParentOu          = Get-JmlDnParent -DistinguishedName ([string]$AdUser.DistinguishedName)
        GivenName         = [string]$AdUser.GivenName
        Surname           = [string]$AdUser.Surname
        DisplayName       = [string]$AdUser.DisplayName
        Department        = [string]$AdUser.Department
        Title             = [string]$AdUser.Title
        ManagerEmployeeId = $managerId
        Enabled           = [bool]$AdUser.Enabled
        ManagedGroups     = $managed
    }
}

# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

function New-JmlAction {
    param(
        [Parameter(Mandatory)][ValidateSet('Joiner', 'Mover', 'Rehire', 'Leaver', 'Orphan', 'Deferred', 'Error')][string]$Action,
        [Parameter(Mandatory)][string]$EmployeeId,
        [string]$DisplayName = '',
        [string]$SamAccountName = '',
        [string]$UserPrincipalName = '',
        [string]$ObjectGuid = '',
        [string]$TargetOu = '',
        [System.Collections.IDictionary]$Attributes = ([ordered]@{}),
        [bool]$SetManager = $false,
        [string]$ManagerId = '',
        [AllowEmptyCollection()][string[]]$GroupsToAdd = @(),
        [AllowEmptyCollection()][string[]]$GroupsToRemove = @(),
        [bool]$MoveOu = $false,
        [AllowEmptyCollection()][string[]]$Changes = @(),
        [AllowEmptyCollection()][string[]]$Warnings = @()
    )
    [pscustomobject]@{
        Action            = $Action
        EmployeeId        = $EmployeeId
        DisplayName       = $DisplayName
        SamAccountName    = $SamAccountName
        UserPrincipalName = $UserPrincipalName
        ObjectGuid        = $ObjectGuid
        TargetOu          = $TargetOu
        MoveOu            = $MoveOu
        Attributes        = $Attributes
        SetManager        = $SetManager
        ManagerId         = $ManagerId
        GroupsToAdd       = @($GroupsToAdd)
        GroupsToRemove    = @($GroupsToRemove)
        Changes           = @($Changes)
        Warnings          = @($Warnings)
    }
}

function New-JmlPlan {
    <#
    .SYNOPSIS
        Compares the HR feed (desired state) with managed AD accounts (current state)
        and returns the actions needed to converge them. Running it against a converged
        directory returns an empty plan, which is what makes the engine idempotent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$HrRecords,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$CurrentUsers,
        [Parameter(Mandatory)]$RoleMap,
        [Parameter(Mandatory)]$Settings,
        [AllowEmptyCollection()][string[]]$TakenSamAccountNames = @(),
        [datetime]$AsOf = (Get-Date).Date
    )

    $actions  = New-Object System.Collections.Generic.List[object]
    $noChange = 0
    $taken = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $TakenSamAccountNames) { if ($s) { [void]$taken.Add($s) } }

    # Index current state by the immutable anchor (employeeID), never by name.
    $current    = @{}
    $conflicted = @{}
    foreach ($u in $CurrentUsers) {
        if ($u.SamAccountName) { [void]$taken.Add($u.SamAccountName) }
        if ($current.ContainsKey($u.EmployeeId)) { $conflicted[$u.EmployeeId] = $true } else { $current[$u.EmployeeId] = $u }
    }
    foreach ($id in @($conflicted.Keys | Sort-Object)) {
        $actions.Add((New-JmlAction -Action 'Error' -EmployeeId $id `
                    -Changes @("employeeID $id is on more than one AD account; fix manually, the engine will not guess")))
    }

    $activeIds = @{}
    foreach ($rec in $HrRecords) { if ($rec.Status -eq 'Active') { $activeIds[$rec.EmployeeId] = $true } }

    $hrIds = @{}
    foreach ($rec in $HrRecords) {
        $hrIds[$rec.EmployeeId] = $true
        if ($conflicted.ContainsKey($rec.EmployeeId)) { continue }

        $existing = $null
        if ($current.ContainsKey($rec.EmployeeId)) { $existing = $current[$rec.EmployeeId] }
        $displayName = "$($rec.FirstName) $($rec.LastName)"

        # ---- Leaver -------------------------------------------------------
        if ($rec.Status -eq 'Terminated') {
            if (-not $existing) { continue }   # never provisioned, nothing to remove
            if ($rec.EndDate -and $rec.EndDate -gt $AsOf) {
                $actions.Add((New-JmlAction -Action 'Deferred' -EmployeeId $rec.EmployeeId -DisplayName $displayName `
                            -SamAccountName $existing.SamAccountName `
                            -Changes @("Termination effective $($rec.EndDate.ToString('yyyy-MM-dd')); no change yet")))
                continue
            }
            $leftover = @($existing.ManagedGroups | Where-Object { $_ })
            $inDisabledOu = $existing.ParentOu -eq $Settings.disabledOu
            if (-not $existing.Enabled -and $inDisabledOu -and $leftover.Count -eq 0) { $noChange++; continue }

            $changes = @('Disable account', 'Revoke Entra sessions', 'Reset password')
            $changes += @($leftover | ForEach-Object { "-$_" })
            if (-not $inDisabledOu) { $changes += "Move to $(Get-JmlDnLeafValue -DistinguishedName $Settings.disabledOu)" }
            $actions.Add((New-JmlAction -Action 'Leaver' -EmployeeId $rec.EmployeeId -DisplayName $existing.DisplayName `
                        -SamAccountName $existing.SamAccountName -UserPrincipalName $existing.UserPrincipalName `
                        -ObjectGuid $existing.ObjectGuid -TargetOu $Settings.disabledOu -MoveOu (-not $inDisabledOu) `
                        -GroupsToRemove $leftover -Changes $changes))
            continue
        }

        # ---- Active: joiner / mover / rehire ------------------------------
        if (-not $existing -and $rec.StartDate -and $rec.StartDate -gt $AsOf) {
            $actions.Add((New-JmlAction -Action 'Deferred' -EmployeeId $rec.EmployeeId -DisplayName $displayName `
                        -Changes @("Starts $($rec.StartDate.ToString('yyyy-MM-dd')); account not created yet")))
            continue
        }
        if (-not (Get-JmlDepartmentRule -RoleMap $RoleMap -Department $rec.Department)) {
            $actions.Add((New-JmlAction -Action 'Error' -EmployeeId $rec.EmployeeId -DisplayName $displayName `
                        -Changes @("Department '$($rec.Department)' is not in role-map.json; skipped")))
            continue
        }

        $desiredGroups = Get-JmlDesiredGroups -Record $rec -RoleMap $RoleMap
        $desiredOu     = Get-JmlDesiredOu -Record $rec -RoleMap $RoleMap -Settings $Settings
        $warnings = @()
        $desiredManager = $rec.ManagerId
        if ($desiredManager -and -not $activeIds.ContainsKey($desiredManager)) {
            $warnings += "Manager $desiredManager is not active in the HR feed; manager left blank"
            $desiredManager = ''
        }
        $desiredAttrs = [ordered]@{
            GivenName   = $rec.FirstName
            Surname     = $rec.LastName
            DisplayName = $displayName
            Department  = $rec.Department
            Title       = $rec.Title
        }

        if (-not $existing) {
            $sam = New-JmlSamAccountName -FirstName $rec.FirstName -LastName $rec.LastName -Taken $taken
            $changes = @("Create in $(Get-JmlDnLeafValue -DistinguishedName $desiredOu)")
            $changes += @($desiredGroups | ForEach-Object { "+$_" })
            if ($desiredManager) { $changes += "Manager: $desiredManager" }
            $actions.Add((New-JmlAction -Action 'Joiner' -EmployeeId $rec.EmployeeId -DisplayName $displayName `
                        -SamAccountName $sam -UserPrincipalName "$sam@$($Settings.upnSuffix)" -TargetOu $desiredOu `
                        -Attributes $desiredAttrs -SetManager ([bool]$desiredManager) -ManagerId $desiredManager `
                        -GroupsToAdd $desiredGroups -Changes $changes -Warnings $warnings))
            continue
        }

        $attrChanges = [ordered]@{}
        $changes = @()
        foreach ($name in @($desiredAttrs.Keys)) {
            $have = "$($existing.$name)"
            $want = [string]$desiredAttrs[$name]
            if ($have -cne $want) {
                $attrChanges[$name] = $want
                $changes += "${name}: '$have' -> '$want'"
            }
        }
        $setManager = "$($existing.ManagerEmployeeId)" -ne $desiredManager
        if ($setManager) { $changes += "Manager: '$($existing.ManagerEmployeeId)' -> '$desiredManager'" }

        $currentGroups = @($existing.ManagedGroups | Where-Object { $_ })
        $toAdd    = @($desiredGroups | Where-Object { $currentGroups -notcontains $_ })
        $toRemove = @($currentGroups | Where-Object { $desiredGroups -notcontains $_ })
        $changes += @($toAdd | ForEach-Object { "+$_" })
        $changes += @($toRemove | ForEach-Object { "-$_" })

        $moveOu = $existing.ParentOu -ne $desiredOu
        if ($moveOu) { $changes += "Move to $(Get-JmlDnLeafValue -DistinguishedName $desiredOu)" }

        $kind = $null
        if (-not $existing.Enabled) {
            $kind = 'Rehire'
            $changes = @('Enable account', 'Reset password') + $changes
        }
        elseif ($changes.Count -gt 0) { $kind = 'Mover' }

        if (-not $kind) { $noChange++; continue }
        $actions.Add((New-JmlAction -Action $kind -EmployeeId $rec.EmployeeId -DisplayName $displayName `
                    -SamAccountName $existing.SamAccountName -UserPrincipalName $existing.UserPrincipalName `
                    -ObjectGuid $existing.ObjectGuid -TargetOu $desiredOu -MoveOu $moveOu -Attributes $attrChanges `
                    -SetManager $setManager -ManagerId $desiredManager -GroupsToAdd $toAdd -GroupsToRemove $toRemove `
                    -Changes $changes -Warnings $warnings))
    }

    # ---- Orphans: enabled in AD, absent from HR. Reported, never auto-disabled.
    foreach ($id in @($current.Keys | Sort-Object)) {
        $u = $current[$id]
        if (-not $hrIds.ContainsKey($id) -and $u.Enabled) {
            $actions.Add((New-JmlAction -Action 'Orphan' -EmployeeId $id -DisplayName $u.DisplayName `
                        -SamAccountName $u.SamAccountName `
                        -Changes @('Enabled in AD but missing from the HR feed; review manually (not auto-disabled)')))
        }
    }

    $sorted = @($actions | Sort-Object @{ Expression = { [array]::IndexOf($script:ActionOrder, $_.Action) } }, EmployeeId)
    $summary = [ordered]@{}
    foreach ($kind in $script:ActionOrder) { $summary[$kind] = @($sorted | Where-Object { $_.Action -eq $kind }).Count }
    $summary['NoChange'] = $noChange

    [pscustomobject]@{
        GeneratedAt = (Get-Date).ToString('o')
        AsOf        = $AsOf.ToString('yyyy-MM-dd')
        Summary     = $summary
        Actions     = $sorted
    }
}

function Test-JmlPlanSafety {
    <#
        Blast-radius guard. A truncated or wrong HR export should never be able to
        disable a big slice of the organization in one run.
    #>
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][int]$EnabledUserCount,
        [Parameter(Mandatory)][double]$MaxPercent
    )
    $reasons = @()
    if ($EnabledUserCount -gt 0) {
        $leavers = @($Plan.Actions | Where-Object { $_.Action -eq 'Leaver' }).Count
        $orphans = @($Plan.Actions | Where-Object { $_.Action -eq 'Orphan' }).Count
        $leaverPct = [math]::Round(100.0 * $leavers / $EnabledUserCount, 1)
        $orphanPct = [math]::Round(100.0 * $orphans / $EnabledUserCount, 1)
        if ($leaverPct -gt $MaxPercent) {
            $reasons += "Plan disables $leavers of $EnabledUserCount enabled accounts ($leaverPct%), above the $MaxPercent% limit"
        }
        if ($orphanPct -gt $MaxPercent) {
            $reasons += "$orphans enabled accounts ($orphanPct%) are missing from the HR feed; the export may be truncated"
        }
    }
    [pscustomobject]@{ Passed = ($reasons.Count -eq 0); Reasons = $reasons }
}

# ---------------------------------------------------------------------------
# Output and logging
# ---------------------------------------------------------------------------

function Show-JmlPlan {
    param([Parameter(Mandatory)]$Plan)
    Write-Host ''
    $counts = @($Plan.Summary.GetEnumerator() | ForEach-Object { "$($_.Value) $($_.Key)" }) -join ' | '
    Write-Host "Plan as of $($Plan.AsOf): $counts"
    if (@($Plan.Actions).Count -eq 0) {
        Write-Host 'No changes. The directory already matches the HR feed.' -ForegroundColor Green
        return
    }
    $Plan.Actions |
        Select-Object Action, EmployeeId, @{ n = 'Account'; e = { $_.SamAccountName } }, DisplayName,
        @{ n = 'Changes'; e = { (@($_.Changes) + @($_.Warnings | ForEach-Object { "WARNING: $_" })) -join '; ' } } |
        Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
}

function Start-JmlLog {
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$RunId)
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }
    $script:RunId = $RunId
    $script:LogPath = Join-Path $Directory "jml-$RunId.jsonl"
    return $script:LogPath
}

function Write-JmlLog {
    <# Structured JSON-lines audit log (one event per line) plus console output. #>
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO',
        [Parameter(Mandatory)][Alias('Event')][string]$EventName,
        [string]$EmployeeId = '',
        [string]$Target = '',
        [string]$Detail = ''
    )
    $entry = [ordered]@{
        ts         = (Get-Date).ToUniversalTime().ToString('o')
        runId      = $script:RunId
        level      = $Level
        event      = $EventName
        employeeId = $EmployeeId
        target     = $Target
        detail     = $Detail
    }
    if ($script:LogPath) {
        $line = ($entry | ConvertTo-Json -Compress) + [Environment]::NewLine
        [IO.File]::AppendAllText($script:LogPath, $line, (New-Object Text.UTF8Encoding $false))
    }
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red' }[$Level]
    Write-Host ('[{0,-5}] {1,-18} {2,-6} {3} {4}' -f $Level, $EventName, $EmployeeId, $Target, $Detail) -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# AI agents: every agent has a human sponsor; when the sponsor goes, so does the agent
# ---------------------------------------------------------------------------

$script:AgentNamePattern = '^[A-Z][A-Z0-9]{1,15}$'

function Import-JmlAgentRegister {
    <# Loads and validates config\agents.json. Fails loudly on anything malformed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Agent register not found: $Path" }
    $register = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $seen = @{}
    foreach ($agent in @($register.agents)) {
        $name = "$($agent.name)"
        if ($name -cnotmatch $script:AgentNamePattern) {
            throw "Invalid agent name '$name' (capital letters and digits, 2-16 characters)"
        }
        if ($seen.ContainsKey($name)) { throw "Duplicate agent name in register: $name" }
        $seen[$name] = $true
        $sponsor = "$($agent.sponsorEmployeeId)".Trim()
        if ($sponsor -and $sponsor -notmatch $script:EmployeeIdPattern) {
            throw "Invalid sponsorEmployeeId '$sponsor' for agent $name"
        }
    }
    return $register
}

function Get-JmlSponsorStatus {
    <# Active, Leaving (termination dated in the future), Gone, or None. #>
    param(
        [AllowEmptyString()][string]$EmployeeId = '',
        [Parameter(Mandatory)][hashtable]$HrById,
        [Parameter(Mandatory)][datetime]$AsOf
    )
    if (-not $EmployeeId) { return [pscustomobject]@{ State = 'None'; Detail = 'it has no human sponsor' } }
    if (-not $HrById.ContainsKey($EmployeeId)) {
        return [pscustomobject]@{ State = 'Gone'; Detail = "sponsor $EmployeeId is not in the HR feed" }
    }
    $rec = $HrById[$EmployeeId]
    $who = "$EmployeeId ($($rec.FirstName) $($rec.LastName))"
    if ($rec.Status -eq 'Terminated') {
        if ($rec.EndDate -and $rec.EndDate -gt $AsOf) {
            return [pscustomobject]@{ State = 'Leaving'; Detail = "sponsor $who leaves on $($rec.EndDate.ToString('yyyy-MM-dd'))" }
        }
        return [pscustomobject]@{ State = 'Gone'; Detail = "sponsor $who left Meridian Orbital" }
    }
    if ($rec.StartDate -and $rec.StartDate -gt $AsOf) {
        return [pscustomobject]@{ State = 'Gone'; Detail = "sponsor $who has not started yet" }
    }
    return [pscustomobject]@{ State = 'Active'; Detail = "sponsor $who" }
}

function New-JmlAgentPlan {
    <#
    .SYNOPSIS
        Decides what happens to each registered agent, given the HR feed and each agent's
        current state in Entra ID. Automation only ever takes agent access away: an agent
        whose sponsor is gone is suspended, and the engine never re-enables an agent.
    .PARAMETER CurrentState
        servicePrincipalId -> @{ Found = $true/$false; Enabled = $true/$false }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Agents,
        [Parameter(Mandatory)][hashtable]$CurrentState,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$HrRecords,
        [datetime]$AsOf = (Get-Date).Date
    )
    $hrById = @{}
    foreach ($rec in $HrRecords) { $hrById[$rec.EmployeeId] = $rec }
    $actions = New-Object System.Collections.Generic.List[object]
    $noChange = 0

    foreach ($agent in $Agents) {
        $spId = "$($agent.servicePrincipalId)"
        $sponsor = Get-JmlSponsorStatus -EmployeeId "$($agent.sponsorEmployeeId)".Trim() -HrById $hrById -AsOf $AsOf
        $base = @{ Agent = "$($agent.name)"; ServicePrincipalId = $spId; AppId = "$($agent.appId)"; Sponsor = $sponsor.Detail }

        if (-not $spId) {
            $actions.Add([pscustomobject]($base + @{ Action = 'AgentUnregistered'; Reason = 'Not in Entra ID yet; run Register-OrbitAgents.ps1'; Note = '' }))
            continue
        }
        $state = $CurrentState[$spId]
        if (-not $state -or -not $state.Found) {
            $actions.Add([pscustomobject]($base + @{ Action = 'AgentError'; Reason = "servicePrincipalId $spId was not found in Entra ID"; Note = '' }))
            continue
        }

        if ($sponsor.State -in 'Gone', 'None') {
            if ($state.Enabled) {
                $note = "Suspended $($AsOf.ToString('yyyy-MM-dd')) by JML Engine: $($sponsor.Detail)."
                $actions.Add([pscustomobject]($base + @{ Action = 'AgentSuspend'; Reason = "Suspend: $($sponsor.Detail)"; Note = $note }))
            }
            else { $noChange++ }
            continue
        }
        if (-not $state.Enabled) {
            $actions.Add([pscustomobject]($base + @{ Action = 'AgentHeld'; Note = '';
                        Reason = 'Disabled while its sponsor is active. The engine never re-enables agents: review it and re-enable it by hand.' }))
            continue
        }
        if ($sponsor.State -eq 'Leaving') {
            $actions.Add([pscustomobject]($base + @{ Action = 'AgentWarn'; Note = '';
                        Reason = "$($sponsor.Detail): assign a new sponsor before then or the agent will be suspended" }))
            continue
        }
        $noChange++
    }

    $order = @('AgentError', 'AgentSuspend', 'AgentWarn', 'AgentHeld', 'AgentUnregistered')
    $sorted = @($actions | Sort-Object @{ Expression = { [array]::IndexOf($order, $_.Action) } }, Agent)
    $summary = [ordered]@{}
    foreach ($kind in $order) { $summary[$kind] = @($sorted | Where-Object { $_.Action -eq $kind }).Count }
    $summary['AgentNoChange'] = $noChange
    [pscustomobject]@{ Summary = $summary; Actions = $sorted }
}

function Show-JmlAgentPlan {
    param([Parameter(Mandatory)]$AgentPlan)
    $counts = @($AgentPlan.Summary.GetEnumerator() | ForEach-Object { "$($_.Value) $($_.Key -replace '^Agent', '')" }) -join ' | '
    Write-Host "Agents: $counts"
    if (@($AgentPlan.Actions).Count -eq 0) {
        Write-Host 'No agent changes needed.' -ForegroundColor Green
        return
    }
    $AgentPlan.Actions | Select-Object Action, Agent, Reason |
        Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
}

Export-ModuleMember -Function Import-HrFeed, ConvertTo-JmlDate, Get-JmlDepartmentRule, Get-JmlManagedGroupNames,
    Get-JmlDesiredGroups, Get-JmlDesiredOu, ConvertTo-JmlDnValue, ConvertTo-JmlLdapFilterValue, Get-JmlDnParent,
    Get-JmlDnLeafValue, New-JmlSamAccountName, New-JmlRandomPassword, ConvertTo-JmlCurrentUser, New-JmlPlan,
    Test-JmlPlanSafety, Show-JmlPlan, Start-JmlLog, Write-JmlLog, Import-JmlAgentRegister, Get-JmlSponsorStatus,
    New-JmlAgentPlan, Show-JmlAgentPlan
