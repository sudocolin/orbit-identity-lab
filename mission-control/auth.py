"""Microsoft Entra ID sign-in (OpenID Connect, authorization code flow) via MSAL.

The app re-verifies every session with Entra every REVALIDATE_SECONDS by redeeming
its refresh token. When an admin (or the JML engine) revokes the user's sessions,
or the account is disabled, that redemption fails and the user is signed out of
Mission Control too, instead of keeping a valid local cookie until it expires.

Pending sign-ins are stored in SQLite, keyed by the OAuth `state` value and bound to
the browser that started them. That makes sign-in survive an app restart, a double
click or a link prefetch, while still refusing a callback that was started in a
different browser (login CSRF).
"""
import logging
import secrets
import time
from urllib.parse import quote

import msal

SCOPES = ["User.Read"]   # MSAL adds openid, profile and offline_access itself
log = logging.getLogger("missioncontrol.auth")

ROLES = [  # highest first
    ("MissionControl.FlightDirector", "Flight Director"),
    ("MissionControl.Operator", "Operator"),
    ("MissionControl.Viewer", "Viewer"),
]


class Auth:
    def __init__(self, settings, store, app_factory=None):
        self.settings = settings
        self.store = store
        self._app_factory = app_factory or self._msal_app
        self.sessions = {}   # sid -> {"cache", "claims", "checked"}

    def _msal_app(self, cache=None):
        s = self.settings
        return msal.ConfidentialClientApplication(
            s.client_id,
            authority=f"https://login.microsoftonline.com/{s.tenant_id}",
            client_credential=s.client_secret,
            token_cache=cache,
        )

    @staticmethod
    def new_sid():
        return secrets.token_urlsafe(32)

    def begin(self, browser_id):
        flow = self._app_factory().initiate_auth_code_flow(
            SCOPES, redirect_uri=self.settings.redirect_uri, prompt="select_account")
        self.store.save_flow(flow["state"], browser_id, flow)
        return flow["auth_uri"]

    def complete(self, browser_id, params):
        """Finishes a sign-in. Returns (new session id, id token claims)."""
        if params.get("error"):
            raise ValueError(params.get("error_description") or params["error"])
        found = self.store.take_flow(params.get("state", ""))
        if not found:
            raise ValueError("This sign-in link expired or was already used. Please sign in again.")
        started_by, flow = found
        if not browser_id or not secrets.compare_digest(started_by, browser_id):
            raise ValueError("This sign-in was started in a different browser. Please sign in again here.")
        cache = msal.SerializableTokenCache()
        result = self._app_factory(cache).acquire_token_by_auth_code_flow(flow, params)
        if "error" in result:
            raise ValueError(result.get("error_description") or result["error"])
        claims = result.get("id_token_claims", {})
        sid = self.new_sid()   # fresh session id after sign-in (no session fixation)
        self.sessions[sid] = {"cache": cache, "claims": claims, "checked": time.time()}
        return sid, claims

    def claims(self, sid):
        session = self.sessions.get(sid)
        return session["claims"] if session else None

    def seconds_since_check(self, sid):
        session = self.sessions.get(sid)
        return int(time.time() - session["checked"]) if session else None

    def still_valid(self, sid):
        """False if Entra no longer honors this user's session (revoked, disabled, deleted)."""
        session = self.sessions.get(sid)
        if not session:
            return False
        if time.time() - session["checked"] < self.settings.revalidate_seconds:
            return True
        app = self._app_factory(session["cache"])
        accounts = app.get_accounts()
        if not accounts:
            return False
        result = app.acquire_token_silent_with_error(SCOPES, account=accounts[0], force_refresh=True)
        if result and "access_token" in result:
            session["checked"] = time.time()
            return True
        error = (result or {}).get("error", "no_refresh_token")
        if error in ("invalid_grant", "interaction_required", "no_refresh_token"):
            log.warning("Session for %s rejected by Entra: %s",
                        session["claims"].get("preferred_username"), error)
            return False
        log.warning("Could not re-verify session (%s); keeping it for now", error)
        return True

    def end(self, sid):
        self.sessions.pop(sid, None)

    def logout_url(self):
        s = self.settings
        return (f"https://login.microsoftonline.com/{s.tenant_id}/oauth2/v2.0/logout"
                f"?post_logout_redirect_uri={quote(s.public_base_url + '/', safe='')}")


def role_of(claims):
    granted = set(claims.get("roles", [])) if claims else set()
    for value, label in ROLES:
        if value in granted:
            return label
    return None
