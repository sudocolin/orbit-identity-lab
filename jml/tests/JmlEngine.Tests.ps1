<#
    Unit tests for the JML planner. No Active Directory required.

    Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
    Invoke-Pester .\jml\tests -Output Detailed
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\JmlEngine.psm1') -Force
    $RoleMap  = Get-Content (Join-Path $PSScriptRoot '..\config\role-map.json') -Raw | ConvertFrom-Json
    $Settings = Get-Content (Join-Path $PSScriptRoot '..\config\settings.example.json') -Raw | ConvertFrom-Json
    $AsOf     = [datetime]'2026-09-26'

    function New-TestRecord {
        param([string]$Id, [string]$First = 'Test', [string]$Last = 'User', [string]$Dept = 'Mission Ops',
            [string]$Title = 'Flight Controller', [string]$Mgr = '', [string]$Status = 'Active', $Start = $null, $End = $null)
        [pscustomobject]@{
            EmployeeId = $Id; FirstName = $First; LastName = $Last; Department = $Dept; Title = $Title
            ManagerId = $Mgr; Status = $Status; StartDate = $Start; EndDate = $End
        }
    }

    # An AD account exactly as the engine would have provisioned the given HR record.
    function New-ConvergedUser {
        param($Record, [string]$Sam, [bool]$Enabled = $true)
        $ou = Get-JmlDesiredOu -Record $Record -RoleMap $RoleMap -Settings $Settings
        [pscustomobject]@{
            EmployeeId = $Record.EmployeeId; SamAccountName = $Sam; UserPrincipalName = "$Sam@lab.test"
            ObjectGuid = [guid]::NewGuid().ToString(); DistinguishedName = "CN=$Sam,$ou"; ParentOu = $ou
            GivenName = $Record.FirstName; Surname = $Record.LastName; DisplayName = "$($Record.FirstName) $($Record.LastName)"
            Department = $Record.Department; Title = $Record.Title; ManagerEmployeeId = $Record.ManagerId
            Enabled = $Enabled; ManagedGroups = @(Get-JmlDesiredGroups -Record $Record -RoleMap $RoleMap)
        }
    }

    function Get-Actions { param($Plan, [string]$Kind) @($Plan.Actions | Where-Object { $_.Action -eq $Kind }) }
    function New-TakenSet { New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase) }
}

Describe 'New-JmlSamAccountName' {
    It 'strips accents and punctuation' {
        $taken = New-TakenSet
        New-JmlSamAccountName -FirstName 'José' -LastName 'Martínez' -Taken $taken | Should -Be 'jmartinez'
        New-JmlSamAccountName -FirstName 'Siobhan' -LastName "O'Neil" -Taken $taken | Should -Be 'soneil'
    }
    It 'numbers collisions instead of failing' {
        $taken = New-TakenSet
        [void]$taken.Add('mchen')
        New-JmlSamAccountName -FirstName 'Maria' -LastName 'Chen' -Taken $taken | Should -Be 'mchen2'
    }
}

Describe 'Get-JmlDesiredGroups' {
    It 'gives payroll specialists payroll access' {
        $r = New-TestRecord -Id 'E1' -Dept 'Finance' -Title 'Payroll Specialist'
        Get-JmlDesiredGroups -Record $r -RoleMap $RoleMap | Should -Contain 'FS-Payroll-Modify'
    }
    It 'keeps Mission Control away from Finance' {
        $groups = Get-JmlDesiredGroups -Record (New-TestRecord -Id 'E1' -Dept 'Finance' -Title 'Accountant') -RoleMap $RoleMap
        $groups | Should -Not -Contain 'APP-MissionControl-Operators'
        $groups | Should -Not -Contain 'APP-MissionControl-Viewers'
    }
    It 'scopes title rules to their departments' {
        $r = New-TestRecord -Id 'E1' -Dept 'Flight Software' -Title 'Flight Director'
        $groups = Get-JmlDesiredGroups -Record $r -RoleMap $RoleMap
        $groups | Should -Contain 'GG-People-Leads'
        $groups | Should -Not -Contain 'APP-MissionControl-FlightDirectors'
    }
}

Describe 'New-JmlPlan' {
    It 'creates joiners with birthright groups' {
        $plan = New-JmlPlan -HrRecords @(New-TestRecord -Id 'E1' -First 'Ana' -Last 'Diaz') -CurrentUsers @() `
            -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        $j = @(Get-Actions $plan 'Joiner')
        $j | Should -HaveCount 1
        $j[0].SamAccountName | Should -Be 'adiaz'
        $j[0].GroupsToAdd | Should -Contain 'APP-MissionControl-Operators'
    }

    It 'defers joiners whose start date is in the future' {
        $rec = New-TestRecord -Id 'E1' -Start ([datetime]'2026-10-19')
        $plan = New-JmlPlan -HrRecords @($rec) -CurrentUsers @() -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        Get-Actions $plan 'Deferred' | Should -HaveCount 1
        Get-Actions $plan 'Joiner' | Should -HaveCount 0
    }

    It 'turns a transfer into a mover: attribute change, group swap, OU move' {
        $before = New-TestRecord -Id 'E1' -Dept 'Mission Ops' -Title 'Flight Controller'
        $after  = New-TestRecord -Id 'E1' -Dept 'Finance' -Title 'Accountant'
        $plan = New-JmlPlan -HrRecords @($after) -CurrentUsers @(New-ConvergedUser $before 'tuser') `
            -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        $m = @(Get-Actions $plan 'Mover')
        $m | Should -HaveCount 1
        $m[0].GroupsToRemove | Should -Contain 'APP-MissionControl-Operators'
        $m[0].GroupsToRemove | Should -Contain 'FS-Telemetry-Read'
        $m[0].GroupsToAdd | Should -Contain 'GG-Finance'
        $m[0].GroupsToAdd | Should -Not -Contain 'GG-All-Crew'
        $m[0].MoveOu | Should -BeTrue
        $m[0].Attributes['Department'] | Should -Be 'Finance'
    }

    It 'disables terminated employees and removes only managed groups' {
        $rec  = New-TestRecord -Id 'E1'
        $user = New-ConvergedUser $rec 'tuser'
        $term = New-TestRecord -Id 'E1' -Status 'Terminated' -End ([datetime]'2026-09-25')
        $plan = New-JmlPlan -HrRecords @($term) -CurrentUsers @($user) -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        $l = @(Get-Actions $plan 'Leaver')
        $l | Should -HaveCount 1
        $l[0].GroupsToRemove | Should -HaveCount @($user.ManagedGroups).Count
        $l[0].TargetOu | Should -Be $Settings.disabledOu
    }

    It 'defers terminations that are not effective yet' {
        $rec  = New-TestRecord -Id 'E1'
        $term = New-TestRecord -Id 'E1' -Status 'Terminated' -End ([datetime]'2026-10-30')
        $plan = New-JmlPlan -HrRecords @($term) -CurrentUsers @(New-ConvergedUser $rec 'tuser') `
            -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        Get-Actions $plan 'Leaver' | Should -HaveCount 0
        Get-Actions $plan 'Deferred' | Should -HaveCount 1
    }

    It 'reports orphans but never disables them' {
        $ghost = New-ConvergedUser (New-TestRecord -Id 'E9') 'ghost'
        $plan = New-JmlPlan -HrRecords @(New-TestRecord -Id 'E1') -CurrentUsers @(
            (New-ConvergedUser (New-TestRecord -Id 'E1') 'tuser'), $ghost) -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        Get-Actions $plan 'Orphan' | Should -HaveCount 1
        Get-Actions $plan 'Leaver' | Should -HaveCount 0
    }

    It 'is idempotent: a converged directory produces no actions' {
        $chief = New-TestRecord -Id 'E1' -First 'Ana' -Last 'Diaz' -Title 'Flight Director'
        $admin = New-TestRecord -Id 'E2' -First 'Bo' -Last 'Lee' -Dept 'IT' -Title 'Systems Administrator' -Mgr 'E1'
        $plan = New-JmlPlan -HrRecords @($chief, $admin) -CurrentUsers @((New-ConvergedUser $chief 'adiaz'), (New-ConvergedUser $admin 'blee')) `
            -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        $plan.Actions | Should -HaveCount 0
        $plan.Summary['NoChange'] | Should -Be 2
    }

    It 'treats a disabled account that HR shows as active as a rehire' {
        $rec  = New-TestRecord -Id 'E1'
        $user = New-ConvergedUser $rec 'tuser' -Enabled $false
        $plan = New-JmlPlan -HrRecords @($rec) -CurrentUsers @($user) -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        Get-Actions $plan 'Rehire' | Should -HaveCount 1
    }

    It 'refuses to guess when two AD accounts share an employeeID' {
        $rec = New-TestRecord -Id 'E1'
        $plan = New-JmlPlan -HrRecords @($rec) -CurrentUsers @((New-ConvergedUser $rec 'one'), (New-ConvergedUser $rec 'two')) `
            -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        Get-Actions $plan 'Error' | Should -HaveCount 1
        @($plan.Actions | Where-Object { $_.Action -ne 'Error' }) | Should -HaveCount 0
    }

    It 'flags an unmapped department instead of guessing' {
        $plan = New-JmlPlan -HrRecords @(New-TestRecord -Id 'E1' -Dept 'Marketing') -CurrentUsers @() `
            -RoleMap $RoleMap -Settings $Settings -AsOf $AsOf
        Get-Actions $plan 'Error' | Should -HaveCount 1
    }
}

Describe 'Test-JmlPlanSafety' {
    It 'trips when a run would disable too many accounts' {
        $plan = [pscustomobject]@{ Actions = @(1..5 | ForEach-Object { [pscustomobject]@{ Action = 'Leaver' } }) }
        (Test-JmlPlanSafety -Plan $plan -EnabledUserCount 20 -MaxPercent 10).Passed | Should -BeFalse
    }
    It 'passes a normal day' {
        $plan = [pscustomobject]@{ Actions = @([pscustomobject]@{ Action = 'Leaver' }) }
        (Test-JmlPlanSafety -Plan $plan -EnabledUserCount 50 -MaxPercent 10).Passed | Should -BeTrue
    }
}

Describe 'Import-HrFeed' {
    It 'rejects duplicate employee IDs' {
        $path = Join-Path $TestDrive 'dupes.csv'
        Set-Content -Path $path -Value @(
            'EmployeeId,FirstName,LastName,Department,Title,ManagerId,Status,StartDate,EndDate',
            'E1,Ana,Diaz,Mission Ops,Flight Controller,,Active,2024-01-08,',
            'E1,Bo,Lee,IT,Systems Administrator,,Active,2024-01-08,')
        { Import-HrFeed -Path $path } | Should -Throw -ExpectedMessage '*Duplicate EmployeeId*'
    }
    It 'rejects IDs that could inject into LDAP filters' {
        $path = Join-Path $TestDrive 'inject.csv'
        Set-Content -Path $path -Value @(
            'EmployeeId,FirstName,LastName,Department,Title,ManagerId,Status,StartDate,EndDate',
            'E1*)(objectClass=*,Ana,Diaz,Mission Ops,Flight Controller,,Active,2024-01-08,')
        { Import-HrFeed -Path $path } | Should -Throw -ExpectedMessage '*Invalid EmployeeId*'
    }
    It 'loads the sample day-2 feed' {
        @(Import-HrFeed -Path (Join-Path $PSScriptRoot '..\data\hr_feed_day2.csv')) | Should -HaveCount 53
    }
}

Describe 'Agents: the sponsor rule' {
    BeforeAll {
        $AgentAsOf = [datetime]'2026-10-10'
        function New-TestAgent { param([string]$Name, [string]$Sponsor, [string]$Sp = "sp-$Name")
            [pscustomobject]@{ name = $Name; sponsorEmployeeId = $Sponsor; appId = "app-$Name"; servicePrincipalId = $Sp } }
        $Hr = @(
            (New-TestRecord -Id 'E1' -First 'Ana' -Last 'Diaz'),
            (New-TestRecord -Id 'E2' -First 'Bo' -Last 'Lee' -Status 'Terminated' -End ([datetime]'2026-10-10')),
            (New-TestRecord -Id 'E3' -First 'Cy' -Last 'Ng' -Status 'Terminated' -End ([datetime]'2026-11-13'))
        )
        function Get-AgentPlan { param($Agents, $State) New-JmlAgentPlan -Agents $Agents -CurrentState $State -HrRecords $Hr -AsOf $AgentAsOf }
    }

    It 'suspends an agent whose sponsor has left' {
        $plan = Get-AgentPlan @(New-TestAgent 'HERMES' 'E2') @{ 'sp-HERMES' = @{ Found = $true; Enabled = $true } }
        $a = @($plan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' })
        $a | Should -HaveCount 1
        $a[0].Note | Should -Be 'Suspended 2026-10-10 by JML Engine: sponsor E2 (Bo Lee) left Meridian Orbital.'
    }
    It 'suspends an agent with no sponsor at all' {
        $plan = Get-AgentPlan @(New-TestAgent 'ORPHAN' '') @{ 'sp-ORPHAN' = @{ Found = $true; Enabled = $true } }
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' }) | Should -HaveCount 1
    }
    It 'suspends an agent whose sponsor vanished from the HR feed' {
        $plan = Get-AgentPlan @(New-TestAgent 'GHOST' 'E9') @{ 'sp-GHOST' = @{ Found = $true; Enabled = $true } }
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' }) | Should -HaveCount 1
    }
    It 'warns ahead of a future-dated sponsor departure but does not suspend yet' {
        $plan = Get-AgentPlan @(New-TestAgent 'VEGA' 'E3') @{ 'sp-VEGA' = @{ Found = $true; Enabled = $true } }
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentWarn' }) | Should -HaveCount 1
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' }) | Should -HaveCount 0
    }
    It 'is idempotent: an already-suspended agent produces no action' {
        $plan = Get-AgentPlan @(New-TestAgent 'HERMES' 'E2') @{ 'sp-HERMES' = @{ Found = $true; Enabled = $false } }
        $plan.Actions | Should -HaveCount 0
        $plan.Summary['AgentNoChange'] | Should -Be 1
    }
    It 'never re-enables an agent, even when its sponsor is active' {
        $plan = Get-AgentPlan @(New-TestAgent 'ATLAS' 'E1') @{ 'sp-ATLAS' = @{ Found = $true; Enabled = $false } }
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentHeld' }) | Should -HaveCount 1
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' }) | Should -HaveCount 0
    }
    It 'leaves a healthy agent alone' {
        $plan = Get-AgentPlan @(New-TestAgent 'ATLAS' 'E1') @{ 'sp-ATLAS' = @{ Found = $true; Enabled = $true } }
        $plan.Actions | Should -HaveCount 0
    }
    It 'reports unregistered agents and identities missing from Entra' {
        $plan = Get-AgentPlan @((New-TestAgent 'NEW' 'E1' ''), (New-TestAgent 'LOST' 'E1')) @{ 'sp-LOST' = @{ Found = $false; Enabled = $false } }
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentUnregistered' }) | Should -HaveCount 1
        @($plan.Actions | Where-Object { $_.Action -eq 'AgentError' }) | Should -HaveCount 1
    }
    It 'loads the real register and rejects bad agent names' {
        @((Import-JmlAgentRegister -Path (Join-Path $PSScriptRoot '..\config\agents.json')).agents) | Should -HaveCount 3
        $bad = Join-Path $TestDrive 'agents.json'
        Set-Content -Path $bad -Value '{"agents":[{"name":"rogue agent","sponsorEmployeeId":"E1"}]}'
        { Import-JmlAgentRegister -Path $bad } | Should -Throw -ExpectedMessage '*Invalid agent name*'
    }
    It 'Day 3 suspends HERMES (sponsor Patrick Doyle) and only HERMES' {
        $feed = @(Import-HrFeed -Path (Join-Path $PSScriptRoot '..\data\hr_feed_day3.csv'))
        $agents = @((Import-JmlAgentRegister -Path (Join-Path $PSScriptRoot '..\config\agents.json')).agents) |
            ForEach-Object { New-TestAgent $_.name $_.sponsorEmployeeId }
        $state = @{}; foreach ($a in $agents) { $state[$a.servicePrincipalId] = @{ Found = $true; Enabled = $true } }
        $plan = New-JmlAgentPlan -Agents $agents -CurrentState $state -HrRecords $feed -AsOf $AgentAsOf
        $suspended = @($plan.Actions | Where-Object { $_.Action -eq 'AgentSuspend' })
        $suspended | Should -HaveCount 1
        $suspended[0].Agent | Should -Be 'HERMES'
        $suspended[0].Note | Should -Be 'Suspended 2026-10-10 by JML Engine: sponsor E1014 (Patrick Doyle) left Meridian Orbital.'
    }
}
