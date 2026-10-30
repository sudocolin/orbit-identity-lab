# Lab setup

How to rebuild the lab from nothing. Phase 1 takes an evening plus a morning. Portal menu names drift, so if a path below doesn't match, use the admin center's search box.

## 1. Domain controller VM

- **Host:** Windows 10/11 Pro or Enterprise with Hyper-V enabled. On Windows Home, use VirtualBox instead.
- **Guest:** Windows Server 2025 (the free 180-day evaluation ISO), with 2 vCPU, 4 GB RAM, and a 60 GB disk.

In the VM, as Administrator:

```powershell
Rename-Computer -NewName DC01 -Restart
# after reboot
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName lab.local -DomainNetbiosName LAB -InstallDns
```

## 2. Entra tenant

1. Create a new Azure free account. It comes with its own tenant, `<name>.onmicrosoft.com`.
2. Create a cloud-only admin account for day-to-day lab work.
3. Create **two break-glass accounts** now. Give them long random passwords and store them offline. They'll be excluded from every Conditional Access policy in Phase 3.
4. **Start the Entra ID P2 trial tonight** (Billing > Licenses > All products > Try / Buy). Conditional Access needs P1 or higher. If no trial is offered, Phase 3 falls back to Security Defaults, and the Conditional Access policies ship as designed JSON instead of deployed policies.

## 3. Directory bootstrap and first sync of HR data

Copy the repo to the DC, then:

```powershell
cd .\orbit-identity-lab\jml
Copy-Item config\settings.example.json config\settings.json
notepad config\settings.json        # set upnSuffix to <name>.onmicrosoft.com
.\Initialize-LabDirectory.ps1 -AddUpnSuffix
.\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day1.csv            # review the plan
.\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day1.csv -Apply
.\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day1.csv            # should say "No changes"
```

The UPN suffix matters: `lab.local` isn't routable, so users are created as `user@<name>.onmicrosoft.com`, and that's the name they sign in to Entra with.

## 4. Entra Cloud Sync

1. In the Entra admin center, open Microsoft Entra Connect > Cloud sync and download the provisioning agent.
2. Install the agent on DC01. Sign in with an account that holds the Hybrid Identity Administrator role.
3. Create a configuration for `lab.local`:
   - Scope it to `OU=Orbit,DC=lab,DC=local` so only Orbit accounts sync.
   - Keep password hash sync on.
4. Use **Provision on demand** on one user (for example `mchen`) to confirm the user lands in Entra. Then enable the configuration.

## 5. Graph app for leaver session revocation

On DC01, create a certificate. The private key is non-exportable and stays on this machine:

```powershell
$cert = New-SelfSignedCertificate -Subject 'CN=JML-Engine' -CertStoreLocation Cert:\CurrentUser\My `
    -KeySpec Signature -KeyLength 2048 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddMonths(6)
Export-Certificate -Cert $cert -FilePath .\jml-engine.cer
$cert.Thumbprint
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users.Actions -Scope CurrentUser
```

In the Entra admin center:

1. Go to App registrations > New registration and name it `JML Engine`.
2. Under Certificates & secrets, upload `jml-engine.cer`.
3. Under API permissions, add Microsoft Graph > **Application** > `User.RevokeSessions.All`, then **Grant admin consent**. This is the only permission the app gets.
4. Copy the tenant ID, client ID, and certificate thumbprint into `config\settings.json`.

## 6. Day-2 run (the demo)

```powershell
.\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day2.csv
.\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day2.csv -Apply -RevokeCloudSessions
```

For the video, first give one leaver (`cdonovan`) a known password and sign in as them in a private browser window. After the apply, show the session getting kicked out: revocation can take a few minutes to land. Then show the "Revoke sign-in sessions" event in the Entra audit logs and the run's `logs\jml-*.jsonl`.

## Tests (any machine, no AD)

```powershell
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
Invoke-Pester .\jml\tests -Output Detailed
```

## 7. The agent crew (Phase 4)

Setup and the Day 3 demo are in [mission-control/agents/README.md](../mission-control/agents/README.md).
