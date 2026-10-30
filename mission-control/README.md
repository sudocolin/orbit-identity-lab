# Mission Control

The internal ops app of Meridian Orbital, a fictional satellite startup. It does no identity work of its own: Microsoft Entra ID does all of it.

| Concern | How |
| --- | --- |
| Sign-in | OpenID Connect (authorization code flow) through MSAL |
| Who has an account | SCIM 2.0 provisioning from Entra (`/scim/v2/Users`) |
| What they can see | App roles assigned through groups the JML engine manages: **Viewer** (fleet status), **Operator** (+ command queue), **Flight Director** (+ go/no-go approvals and the provisioning log) |
| Staying signed in | Every session is re-verified with Entra every 60 seconds. Revoked or disabled users are signed out of the app, not just out of Microsoft 365. |
| Losing access | When Entra deactivates the account over SCIM, the user is blocked on their next click, even mid-session |
| AI agents | Agents call `/api/v1/...` with their own Entra tokens. Each call checks the token, the agent's live status in Entra ID, and its app roles. Agents can propose commands; only a human Flight Director can approve them. See [agents/README.md](agents/README.md) |

## Run it (Windows)

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python make_secrets.py          # creates .env with a random SCIM token + session secret
tailscale funnel --bg 8000                    # public HTTPS URL Entra can reach; put it in PUBLIC_BASE_URL
.venv\Scripts\python -m uvicorn app:app --port 8000
```

Fill in `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` and `PUBLIC_BASE_URL` in `.env`. The file is git-ignored.

## Entra setup (summary)

1. **Enterprise applications > New application > Create your own application.** Name it *Mission Control* and choose the non-gallery option.
2. **App registrations > Mission Control:**
   - Add a **Web** redirect URI `<PUBLIC_BASE_URL>/auth/callback`.
   - Create a client secret.
   - Create three app roles, `MissionControl.Viewer`, `MissionControl.Operator` and `MissionControl.FlightDirector`, with member type Users/Groups.
3. **Enterprise app > Properties:** set *Assignment required* to **Yes**. Under **Users and groups**, assign `APP-MissionControl-Viewers` → Viewer, `APP-MissionControl-Operators` → Operator, and `APP-MissionControl-FlightDirectors` → Flight Director.
4. **Provisioning:**
   - Set it to Automatic, with Tenant URL `<PUBLIC_BASE_URL>/scim/v2` and Secret token = `SCIM_TOKEN`, then **Test connection**.
   - Under Mappings, turn off *Provision Microsoft Entra ID Groups*.
   - Set Scope to *Sync only assigned users and groups*, then turn provisioning **On**.

## Tests

```powershell
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q tests
```

47 tests, covering the SCIM endpoint (including Entra's quirks, like `"active": "False"` arriving as a string), role-based views, mid-session deprovisioning, revoked-session kick-out, agent token validation (real signed JWTs), suspended agents, command approvals, and sign-in edge cases. No tenant is needed to run them.
