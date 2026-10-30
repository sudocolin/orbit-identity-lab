"""Agent API: AI agents call Mission Control with their own Entra ID identity.

Every call goes through the same checks, in this order:

1. The bearer token is a real Entra access token for this API: signature, expiry,
   audience, issuer and tenant are all verified.
2. It is an app-only token (an agent), not a user's token.
3. The agent is looked up live in Entra ID (cached for a few seconds). Unknown
   identities, identities not governed by the lifecycle engine (no OrbitAgent tag),
   and suspended agents are refused - even while their token is still valid.
   Token expiry alone is not a revocation mechanism: an app-only token stays valid
   for 60-90 minutes after the agent is disabled.
4. The agent must hold the app role the endpoint needs.

Some actions are never available to agents, whatever roles they hold: approving or
rejecting a command (humans only) and reading crew records (personal data).
Every call, allowed or denied, is written to the activity log.
"""
import logging
import threading
import time
from dataclasses import dataclass, field

import jwt
import msal
import requests
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

AGENT_TAG = "OrbitAgent"
ROLE_TELEMETRY = "Agent.Telemetry.Read"
ROLE_PROPOSE = "Agent.Commands.Propose"
GRAPH = "https://graph.microsoft.com/v1.0"
SP_FIELDS = "id,appId,displayName,accountEnabled,tags,notes"

log = logging.getLogger("missioncontrol.agents")


class AgentDenied(Exception):
    def __init__(self, status, error, message, agent_name="unknown", action=""):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message
        self.agent_name, self.action = agent_name, action


class DirectoryUnavailable(Exception):
    pass


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------

class EntraKeyResolver:
    """Finds the Entra signing key for a token (keys are cached by PyJWKClient)."""

    def __init__(self, tenant_id):
        base = f"https://login.microsoftonline.com/{tenant_id}/discovery"
        self._clients = [jwt.PyJWKClient(f"{base}/v2.0/keys", cache_keys=True, lifespan=3600),
                         jwt.PyJWKClient(f"{base}/keys", cache_keys=True, lifespan=3600)]

    def __call__(self, token):
        last = None
        for client in self._clients:
            try:
                return client.get_signing_key_from_jwt(token).key
            except jwt.PyJWKClientError as exc:
                last = exc
        raise jwt.InvalidTokenError(f"signing key not found ({last})")


class AgentTokenValidator:
    def __init__(self, settings, key_resolver=None, leeway=60):
        tid = settings.tenant_id
        self.tenant_id = tid
        self.audiences = [settings.client_id, f"api://{settings.client_id}"]
        self.issuers = [f"https://sts.windows.net/{tid}/", f"https://login.microsoftonline.com/{tid}/v2.0"]
        self.key_resolver = key_resolver or EntraKeyResolver(tid)
        self.leeway = leeway

    def validate(self, token):
        key = self.key_resolver(token)
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.audiences, issuer=self.issuers,
                            leeway=self.leeway, options={"require": ["exp", "iat", "aud", "iss"]})
        if claims.get("tid") != self.tenant_id:
            raise jwt.InvalidTokenError("token is from a different tenant")
        return claims


# ---------------------------------------------------------------------------
# Live agent status from Entra (Microsoft Graph, app-only, Application.Read.All)
# ---------------------------------------------------------------------------

class AgentDirectory:
    def __init__(self, settings, ttl=15, app_factory=None, http=None):
        self.settings = settings
        self.ttl = ttl
        self._app_factory = app_factory or (lambda: msal.ConfidentialClientApplication(
            settings.client_id, authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
            client_credential=settings.client_secret))
        self._app = None
        self._http = http or requests.Session()
        self._cache = {}
        self._lock = threading.Lock()

    def _get(self, url):
        if self._app is None:
            self._app = self._app_factory()
        result = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        if "access_token" not in result:
            raise DirectoryUnavailable(result.get("error_description") or result.get("error") or "no Graph token")
        try:
            response = self._http.get(url, headers={"Authorization": f"Bearer {result['access_token']}"}, timeout=8)
        except requests.RequestException as exc:
            raise DirectoryUnavailable(str(exc))
        return response

    def _cached(self, key, loader):
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1]
        value = loader()
        with self._lock:
            self._cache[key] = (now, value)
        return value

    def lookup(self, object_id):
        """The agent's service principal, or None if it doesn't exist."""
        def load():
            response = self._get(f"{GRAPH}/servicePrincipals/{object_id}?$select={SP_FIELDS}")
            if response.status_code == 404:
                return None
            if response.status_code != 200:
                raise DirectoryUnavailable(f"Graph returned {response.status_code}: {response.text[:200]}")
            return response.json()
        return self._cached(("sp", object_id), load)

    def roster(self):
        """Every service principal tagged as an Orbit agent."""
        def load():
            response = self._get(f"{GRAPH}/servicePrincipals?$filter=tags/any(t:t eq '{AGENT_TAG}')&$select={SP_FIELDS}")
            if response.status_code != 200:
                raise DirectoryUnavailable(f"Graph returned {response.status_code}: {response.text[:200]}")
            return response.json().get("value", [])
        return self._cached(("roster",), load)


def sponsor_of(entry):
    for tag in (entry or {}).get("tags") or []:
        if tag.startswith("Sponsor:"):
            return tag.split(":", 1)[1]
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@dataclass
class Agent:
    name: str
    object_id: str
    app_id: str
    roles: list
    entry: dict
    claims: dict = field(repr=False, default_factory=dict)


def build_agent_router(store, validator, directory, fleet):
    router = APIRouter(prefix="/api/v1")
    targets = {f"{s['id']} {s['name']}" for s in fleet}

    def authenticate(request, action, required_role=None):
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise AgentDenied(401, "missing_token", "Send an Entra ID access token as a Bearer token.", action=action)
        try:
            claims = validator.validate(header[7:].strip())
        except jwt.ExpiredSignatureError:
            raise AgentDenied(401, "token_expired", "The access token has expired.", action=action)
        except jwt.InvalidTokenError as exc:
            raise AgentDenied(401, "invalid_token", f"Token rejected: {exc}", action=action)

        app_id = claims.get("azp") or claims.get("appid") or "unknown-app"
        if "scp" in claims:
            raise AgentDenied(403, "user_token", "This API only accepts agent (app-only) tokens, not a person's token.",
                              agent_name=claims.get("upn") or claims.get("preferred_username") or app_id, action=action)

        object_id = claims.get("oid", "")
        try:
            entry = directory.lookup(object_id)
        except DirectoryUnavailable as exc:
            log.warning("Agent status check failed: %s", exc)
            raise AgentDenied(503, "status_unavailable",
                              "Mission Control can't confirm this agent's status with Entra ID right now, so the call "
                              "is denied by default.", agent_name=app_id, action=action)
        name = (entry or {}).get("displayName") or claims.get("app_displayname") or app_id

        if not entry:
            raise AgentDenied(403, "unknown_agent", "This identity doesn't exist in the tenant.", name, action)
        if AGENT_TAG not in (entry.get("tags") or []):
            raise AgentDenied(403, "not_governed",
                              f"{name} isn't a registered Orbit agent. Only agents governed by the lifecycle engine "
                              "may call this API.", name, action)
        if not entry.get("accountEnabled", False):
            minutes = max(0, int((claims.get("exp", time.time()) - time.time()) // 60))
            reason = (entry.get("notes") or "").strip()
            raise AgentDenied(403, "agent_suspended",
                              f"{name} is suspended in Entra ID. Its token is still valid for {minutes} more minutes, "
                              f"but Mission Control checks every agent's live status.{(' ' + reason) if reason else ''}",
                              name, action)

        roles = list(claims.get("roles") or [])
        store.agent_seen(object_id, app_id, name, roles)
        if required_role and required_role not in roles:
            raise AgentDenied(403, "missing_role", f"{name} doesn't hold the {required_role} role.", name, action)
        return Agent(name, object_id, app_id, roles, entry, claims)

    @router.get("/whoami")
    async def whoami(request: Request):
        agent = authenticate(request, "GET /whoami")
        store.log("AgentCall", agent.name, "GET /whoami")
        return {"name": agent.name, "appId": agent.app_id, "objectId": agent.object_id, "roles": agent.roles,
                "sponsor": sponsor_of(agent.entry), "status": "active",
                "tokenExpiresInMinutes": max(0, int((agent.claims.get("exp", 0) - time.time()) // 60))}

    @router.get("/telemetry")
    async def telemetry(request: Request):
        agent = authenticate(request, "GET /telemetry", ROLE_TELEMETRY)
        store.log("AgentCall", agent.name, "GET /telemetry")
        return {"fleet": fleet, "commands": [{k: c[k] for k in ("id", "target", "action", "state", "proposed_by")}
                                            for c in store.commands()]}

    @router.post("/commands", status_code=201)
    async def propose(request: Request):
        agent = authenticate(request, "POST /commands", ROLE_PROPOSE)
        try:
            body = await request.json()
        except Exception:
            body = None
        if not isinstance(body, dict):
            raise AgentDenied(400, "bad_request", "Send a JSON object with target, action and rationale.",
                              agent.name, "POST /commands")
        target = str(body.get("target", "")).strip()
        action = " ".join(str(body.get("action", "")).split())
        rationale = " ".join(str(body.get("rationale", "")).split())
        if target not in targets:
            raise AgentDenied(400, "bad_target", f"Unknown target. Use one of: {', '.join(sorted(targets))}.",
                              agent.name, "POST /commands")
        if not 3 <= len(action) <= 160 or len(rationale) > 400:
            raise AgentDenied(400, "bad_request", "action must be 3-160 characters and rationale at most 400.",
                              agent.name, "POST /commands")
        command = store.propose(target, action, rationale, agent.name, "agent")
        store.log("AgentProposed", agent.name, f"{command['id']} {target}: {action}")
        return JSONResponse({"id": command["id"], "state": command["state"],
                             "message": "Proposed. A human Flight Director must approve it."}, status_code=201)

    async def decide(request: Request, command_id: str, verb: str):
        action = f"POST /commands/{command_id}/{verb}"
        agent = authenticate(request, action)
        raise AgentDenied(403, "humans_only",
                          f"Only a human Flight Director can {verb} commands. {agent.name} can propose, not decide.",
                          agent.name, action)

    @router.post("/commands/{command_id}/approve")
    async def approve(request: Request, command_id: str):
        return await decide(request, command_id, "approve")

    @router.post("/commands/{command_id}/reject")
    async def reject(request: Request, command_id: str):
        return await decide(request, command_id, "reject")

    @router.get("/crew")
    async def crew(request: Request):
        agent = authenticate(request, "GET /crew")
        raise AgentDenied(403, "personal_data",
                          "Crew records contain personal information and are never available to agents.",
                          agent.name, "GET /crew")

    return router


def agent_denied_response(store, exc):
    store.log("AgentDenied", exc.agent_name, f"{exc.action}: {exc.error}")
    return JSONResponse({"error": exc.error, "message": exc.message, "agent": exc.agent_name},
                        status_code=exc.status)
