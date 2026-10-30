# The agent crew

Three AI agents work at Meridian Orbital. Each one has its own identity in Microsoft Entra ID, a human sponsor who answers for it, and only the access its job needs.

| Agent | Job | Sponsor | Roles |
| --- | --- | --- | --- |
| ATLAS | Watches satellite telemetry and flags anomalies | E1006 Angela Russo | `Agent.Telemetry.Read` |
| VEGA | Drafts satellite commands for a Flight Director to approve | E1009 Hannah Brooks | `Agent.Telemetry.Read`, `Agent.Commands.Propose` |
| HERMES | Writes the morning brief with a local LLM (Ollama) | E1014 Patrick Doyle | `Agent.Telemetry.Read` |

No role lets an agent approve a command or read crew records. Those actions don't exist for agents.

## How it fits together

1. **Identity.** `make_certs.py` creates a certificate per agent on the computer that runs it. The private key stays there; only the public certificate goes to Entra ID. `jml/Register-OrbitAgents.ps1` runs as the JML Engine and creates each agent's identity, tagged `OrbitAgent` with its sponsor.
2. **Access.** A human admin grants each agent its Mission Control roles (API permissions + admin consent). The engine can't grant access to anyone.
3. **Calls.** An agent signs in with its certificate (client-credentials flow) and calls `/api/v1/...` on Mission Control. Every call checks the token, the agent's live status in Entra ID, and its roles. Everything is logged on the Flight Director's **Agents** page.
4. **Lifecycle.** `Invoke-JmlSync.ps1 -ManageAgents` suspends any agent whose sponsor has left, in the same run that offboards the sponsor. Mission Control refuses the agent on its next call, even with a still-valid token.

## Setup

### On the PC (where Mission Control runs)

```powershell
cd C:\orbit-identity-lab\mission-control
.venv\Scripts\python -m pip install -r requirements.txt     # adds PyJWT and requests
.venv\Scripts\python agents\make_certs.py                   # one certificate per agent
```

Copy the three `.cer` files from `C:\orbit-identity-lab\jml\agents\` to the same folder on the domain controller.

### In Entra (Mission Control's app registration)

1. **Expose an API > Application ID URI > Add** and keep the default `api://<client id>`.
2. **App roles > Create app role**, twice, with allowed member types **Applications**:
   - `Agent.Telemetry.Read` (display name: Agent - read telemetry)
   - `Agent.Commands.Propose` (display name: Agent - propose commands)
3. **API permissions > Add a permission > Microsoft Graph > Application permissions > `Application.Read.All`**, then **Grant admin consent**. Mission Control uses it to read each agent's live status.

### In Entra (JML Engine's app registration)

**API permissions > Add a permission > Microsoft Graph > Application permissions > `Application.ReadWrite.OwnedBy`**, then **Grant admin consent**. The engine now holds exactly two permissions.

### On the domain controller

```powershell
cd C:\orbit-identity-lab\jml
.\Register-OrbitAgents.ps1
```

Copy the updated `config\agents.json` back to the PC (same path). It now holds each agent's app ID.

### In Entra (each agent, by a human)

For each of **ATLAS (AI agent)**, **VEGA (AI agent)** and **HERMES (AI agent)** under App registrations: **API permissions > Add a permission > APIs my organization uses > Mission Control > Application permissions**, tick the roles from the table above, **Add permissions**, then **Grant admin consent**.

## Run the agents (PC, with Mission Control running)

```powershell
cd C:\orbit-identity-lab\mission-control
.venv\Scripts\python agents\orbit_agent.py ATLAS whoami
.venv\Scripts\python agents\orbit_agent.py ATLAS probe          # what may ATLAS do?
.venv\Scripts\python agents\orbit_agent.py VEGA probe
.venv\Scripts\python agents\orbit_agent.py VEGA propose --target "MO-3 Petrel" --action "Exit safe mode, resume imaging" --rationale "Battery back above 60%"
.venv\Scripts\python agents\orbit_agent.py VEGA approve CMD-313     # refused: humans only
.venv\Scripts\python agents\orbit_agent.py HERMES brief --loop 20   # keeps running until it loses access
```

HERMES uses Ollama at `http://127.0.0.1:11434` and the first model it finds. Set `OLLAMA_URL` or `OLLAMA_MODEL` in `.env` to change that. If Ollama isn't reachable, HERMES writes a plain summary instead. Briefs are saved to `agents\out\`.

## Day 3: the sponsor leaves

With HERMES running in one window, run this on the domain controller:

```powershell
.\Invoke-JmlSync.ps1 -HrFeed .\data\hr_feed_day3.csv -Apply -RevokeCloudSessions -ManageAgents
```

Patrick Doyle is disabled and his sessions revoked; HERMES is suspended in the same run. Within about 15 seconds HERMES's next call is refused and it stops with **ACCESS REVOKED**. Its token is still valid; Mission Control refuses it anyway because it checks the agent's live status.

## Why not Microsoft Entra Agent ID?

Entra Agent ID is the native home for agent identities, but governing agents with Conditional Access needs Microsoft Agent 365 or Microsoft 365 E7 licensing, which this lab's trial doesn't include. The same principles (own identity, sponsor, least privilege, lifecycle) are built here with app registrations and app roles, and enforced by the API itself. Moving the agents to Agent ID is on the roadmap.
