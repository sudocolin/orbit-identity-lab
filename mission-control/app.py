"""Mission Control: the internal ops app of Meridian Orbital, a fictional satellite startup.

Identity is entirely Entra ID's job:
  * sign-in      -> OpenID Connect (auth.py)
  * who exists   -> SCIM provisioning from Entra (scim.py)
  * what you see -> app roles from group assignment (Viewer / Operator / Flight Director)
  * AI agents    -> their own Entra identities, app roles and a live status check (agents_api.py)
"""
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from agents_api import (AgentDenied, AgentDirectory, AgentTokenValidator, DirectoryUnavailable,
                        agent_denied_response, build_agent_router, sponsor_of)
from auth import Auth, role_of
from scim import ScimError, build_router, error_response
from store import Store

HERE = Path(__file__).parent
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Fictional fleet. The command queue lives in the store.
FLEET = [
    {"id": "MO-1", "name": "Kestrel", "mission": "Earth observation", "status": "Nominal", "battery": "94%", "next_pass": "14:20 UTC", "station": "Svalbard"},
    {"id": "MO-2", "name": "Wren", "mission": "Comms relay", "status": "Nominal", "battery": "88%", "next_pass": "15:05 UTC", "station": "Punta Arenas"},
    {"id": "MO-3", "name": "Petrel", "mission": "Hyperspectral imaging", "status": "Safe mode", "battery": "61%", "next_pass": "14:47 UTC", "station": "Svalbard"},
    {"id": "MO-4", "name": "Tern", "mission": "Tech demo", "status": "Commissioning", "battery": "79%", "next_pass": "16:12 UTC", "station": "Hawaii"},
]


@dataclass
class Settings:
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    public_base_url: str = ""      # e.g. https://my-pc.tailnet-name.ts.net
    scim_token: str = ""
    session_secret: str = ""
    revalidate_seconds: int = 60
    agent_status_seconds: int = 15
    cookie_secure: bool = True
    db_path: str = str(HERE / "missioncontrol.db")

    @property
    def redirect_uri(self):
        return f"{self.public_base_url}/auth/callback"

    @classmethod
    def from_env(cls):
        load_dotenv(HERE / ".env")
        s = cls(
            tenant_id=os.getenv("TENANT_ID", ""),
            client_id=os.getenv("CLIENT_ID", ""),
            client_secret=os.getenv("CLIENT_SECRET", ""),
            public_base_url=os.getenv("PUBLIC_BASE_URL", "").rstrip("/"),
            scim_token=os.getenv("SCIM_TOKEN", ""),
            session_secret=os.getenv("SESSION_SECRET", ""),
            revalidate_seconds=int(os.getenv("REVALIDATE_SECONDS", "60")),
            agent_status_seconds=int(os.getenv("AGENT_STATUS_SECONDS", "15")),
            cookie_secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
            db_path=os.getenv("DB_PATH", str(HERE / "missioncontrol.db")),
        )
        missing = [k for k in ("tenant_id", "client_id", "client_secret", "public_base_url", "scim_token", "session_secret")
                   if not getattr(s, k)]
        if missing:
            raise SystemExit(f"Missing settings in .env: {', '.join(m.upper() for m in missing)}")
        if len(s.scim_token) < 32:
            raise SystemExit("SCIM_TOKEN must be at least 32 characters. Run: python make_secrets.py")
        return s


HUMAN_EVENTS = ("Create", "Update", "Replace", "Delete", "SignIn", "CommandApproved", "CommandRejected")


def create_app(settings, store=None, auth=None, validator=None, directory=None):
    store = store or Store(settings.db_path)
    auth = auth or Auth(settings, store)
    validator = validator or AgentTokenValidator(settings)
    directory = directory or AgentDirectory(settings, ttl=settings.agent_status_seconds)
    templates = Jinja2Templates(directory=str(HERE / "templates"))

    app = FastAPI(title="Mission Control", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, session_cookie="mc_session",
                       same_site="lax", https_only=settings.cookie_secure, max_age=8 * 3600)
    app.include_router(build_router(settings, store))
    app.include_router(build_agent_router(store, validator, directory, FLEET))
    app.state.store, app.state.auth = store, auth

    @app.exception_handler(ScimError)
    async def scim_error_handler(request, exc):
        return error_response(exc)

    @app.exception_handler(AgentDenied)
    async def agent_denied_handler(request, exc):
        return agent_denied_response(store, exc)

    def page(request, name, status=200, **context):
        return templates.TemplateResponse(request, name, context, status_code=status)

    def blocked(request, sid, title, message):
        auth.end(sid)
        request.session.clear()
        return page(request, "message.html", status=403, title=title, message=message)

    def current(request):
        """Returns (claims, record, role) for a signed-in user with access, or a response."""
        sid = request.session.get("sid")
        claims = auth.claims(sid) if sid else None
        if not claims:
            return None, RedirectResponse("/", status_code=303)
        if not auth.still_valid(sid):
            return None, blocked(request, sid, "Your session was ended",
                                 "Your organization revoked your sign-in sessions or disabled your account. "
                                 "You've been signed out of Mission Control.")
        record = store.by_user_name(claims.get("preferred_username", ""))
        if not record or not record["active"]:
            return None, blocked(request, sid, "Access removed",
                                 "Your access to Mission Control has been removed. If you think this is a "
                                 "mistake, contact the IT service desk.")
        role = role_of(claims)
        if not role:
            return None, blocked(request, sid, "No role assigned",
                                 "You're provisioned, but you have no Mission Control role. Contact the IT service desk.")
        return (claims, record, role, sid), None

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        if request.session.get("sid") and auth.claims(request.session["sid"]):
            user, response = current(request)
            if response:
                return response
            claims, record, role, sid = user
            commands = store.commands() if role in ("Operator", "Flight Director") else []
            waiting = sum(1 for c in commands if c["state"] == "Awaiting Flight Director")
            return page(request, "dashboard.html", record=record, role=role, fleet=FLEET, commands=commands,
                        waiting=waiting, csrf=request.session.get("csrf", ""),
                        checked=auth.seconds_since_check(sid), every=settings.revalidate_seconds)
        return page(request, "signin.html")

    @app.post("/commands/{command_id}/decide")
    async def decide(request: Request, command_id: str, decision: str = Form(...), csrf: str = Form("")):
        user, response = current(request)
        if response:
            return response
        claims, record, role, sid = user
        expected = request.session.get("csrf", "")
        if not expected or not secrets.compare_digest(csrf, expected):
            return page(request, "message.html", status=400, title="Request expired",
                        message="That form was out of date. Go back and try again.")
        if role != "Flight Director":
            return page(request, "message.html", status=403, title="Flight Directors only",
                        message="Only a Flight Director can approve or reject commands.")
        approved = decision == "approve"
        if store.decide(command_id, approved, record["display_name"] or record["user_name"]):
            command = store.command(command_id)
            store.log("CommandApproved" if approved else "CommandRejected", record["user_name"],
                      f"{command_id} proposed by {command['proposed_by']}")
        return RedirectResponse("/", status_code=303)

    @app.get("/agents", response_class=HTMLResponse)
    async def agents(request: Request):
        user, response = current(request)
        if response:
            return response
        claims, record, role, sid = user
        if role != "Flight Director":
            return page(request, "message.html", status=403, title="Flight Directors only",
                        message="The agent roster is visible to Flight Directors.")
        seen = {a["object_id"]: a for a in store.agents_seen()}
        roster, error = [], None
        try:
            entries = directory.roster()
        except DirectoryUnavailable as exc:
            entries, error = [], f"Couldn't read the agent roster from Entra ID: {exc}"
        for entry in sorted(entries, key=lambda e: e.get("displayName") or ""):
            local = seen.get(entry.get("id"), {})
            roster.append({"name": entry.get("displayName"), "app_id": entry.get("appId"),
                           "enabled": entry.get("accountEnabled", False), "sponsor": sponsor_of(entry),
                           "notes": entry.get("notes") or "", "roles": local.get("roles", []),
                           "last_seen": local.get("last_seen")})
        return page(request, "agents.html", record=record, role=role, roster=roster, error=error,
                    events=store.events(40, prefix="Agent"))

    @app.get("/login")
    async def login(request: Request):
        browser_id = request.session.get("bid") or secrets.token_urlsafe(24)
        request.session["bid"] = browser_id   # stays the same across sign-ins in this browser
        return RedirectResponse(auth.begin(browser_id), status_code=303)

    @app.get("/auth/callback")
    async def callback(request: Request):
        try:
            sid, claims = auth.complete(request.session.get("bid"), dict(request.query_params))
        except ValueError as exc:
            return page(request, "message.html", status=400, title="Sign-in didn't complete", message=str(exc))
        request.session["sid"] = sid
        request.session["csrf"] = secrets.token_urlsafe(24)
        store.log("SignIn", claims.get("preferred_username"), role_of(claims) or "no role")
        return RedirectResponse("/", status_code=303)

    @app.get("/crew", response_class=HTMLResponse)
    async def crew(request: Request):
        user, response = current(request)
        if response:
            return response
        claims, record, role, sid = user
        return page(request, "crew.html", record=record, role=role, people=store.all(),
                    events=store.events(15, actions=HUMAN_EVENTS) if role == "Flight Director" else [])

    @app.get("/logout")
    async def logout(request: Request):
        sid = request.session.get("sid")
        if sid:
            auth.end(sid)
        browser_id = request.session.get("bid")
        request.session.clear()
        if browser_id:
            request.session["bid"] = browser_id
        return RedirectResponse(auth.logout_url(), status_code=303)

    @app.get("/healthz")
    async def healthz():
        return JSONResponse({"ok": True})

    return app


if __name__ != "__main__" and os.getenv("MISSIONCONTROL_NO_AUTOAPP") != "1":
    app = create_app(Settings.from_env())
