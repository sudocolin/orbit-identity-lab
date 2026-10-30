"""Agent API, command approvals, and the sign-in fix. Tokens are real RS256 JWTs signed by a
test key, so signature, audience, issuer and expiry checks all run for real."""
import base64
import json
import os
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["MISSIONCONTROL_NO_AUTOAPP"] = "1"
from agents_api import AgentDirectory, AgentTokenValidator, DirectoryUnavailable  # noqa: E402
from app import Settings, create_app  # noqa: E402
from auth import Auth  # noqa: E402
from store import Store  # noqa: E402

TENANT = "11111111-1111-1111-1111-111111111111"
MC_APP = "22222222-2222-2222-2222-222222222222"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

AGENTS = {
    "oid-atlas": {"id": "oid-atlas", "appId": "app-atlas", "displayName": "ATLAS (AI agent)", "accountEnabled": True,
                  "tags": ["OrbitAgent", "Sponsor:E1006"], "notes": ""},
    "oid-vega": {"id": "oid-vega", "appId": "app-vega", "displayName": "VEGA (AI agent)", "accountEnabled": True,
                 "tags": ["OrbitAgent", "Sponsor:E1009"], "notes": ""},
    "oid-hermes": {"id": "oid-hermes", "appId": "app-hermes", "displayName": "HERMES (AI agent)", "accountEnabled": True,
                   "tags": ["OrbitAgent", "Sponsor:E1014"], "notes": ""},
    "oid-rogue": {"id": "oid-rogue", "appId": "app-rogue", "displayName": "Some script", "accountEnabled": True,
                  "tags": [], "notes": ""},
}


class FakeDirectory:
    def __init__(self):
        self.entries = json.loads(json.dumps(AGENTS))
        self.down = False

    def lookup(self, oid):
        if self.down:
            raise DirectoryUnavailable("Graph is down")
        return self.entries.get(oid)

    def roster(self):
        return [e for e in self.entries.values() if "OrbitAgent" in e["tags"]]


def token(oid="oid-atlas", roles=("Agent.Telemetry.Read",), aud=f"api://{MC_APP}", v1=True, key=KEY,
          exp_in=3600, tid=TENANT, extra=None):
    now = int(time.time())
    claims = {"aud": aud, "iss": f"https://sts.windows.net/{TENANT}/" if v1 else f"https://login.microsoftonline.com/{TENANT}/v2.0",
              "iat": now, "nbf": now, "exp": now + exp_in, "tid": tid, "oid": oid, "roles": list(roles),
              ("appid" if v1 else "azp"): AGENTS.get(oid, {}).get("appId", "app-x")}
    claims.update(extra or {})
    return jwt.encode(claims, key, algorithm="RS256")


def auth_header(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def env(tmp_path):
    settings = Settings(tenant_id=TENANT, client_id=MC_APP, client_secret="s", public_base_url="https://lab.test",
                        scim_token="t" * 48, session_secret="x" * 32, cookie_secure=False)
    store = Store(str(tmp_path / "t.db"))
    directory = FakeDirectory()
    validator = AgentTokenValidator(settings, key_resolver=lambda t: KEY.public_key())
    auth = Auth(settings, store)
    client = TestClient(create_app(settings, store=store, auth=auth, validator=validator, directory=directory))
    return client, store, directory, auth


def last_event(store):
    return store.events(1)[0]


# --- token checks -------------------------------------------------------------

def test_valid_agent_token_reads_telemetry(env):
    client, store, *_ = env
    r = client.get("/api/v1/telemetry", headers=auth_header(token()))
    assert r.status_code == 200 and r.json()["fleet"][0]["name"] == "Kestrel"
    assert last_event(store)["action"] == "AgentCall"


def test_v2_token_with_client_id_audience_is_accepted(env):
    client, *_ = env
    assert client.get("/api/v1/telemetry", headers=auth_header(token(aud=MC_APP, v1=False))).status_code == 200


@pytest.mark.parametrize("kwargs, error", [
    ({"key": OTHER_KEY}, "invalid_token"),
    ({"aud": "api://some-other-api"}, "invalid_token"),
    ({"tid": "99999999-0000-0000-0000-000000000000"}, "invalid_token"),
    ({"exp_in": -600}, "token_expired"),
])
def test_bad_tokens_are_rejected(env, kwargs, error):
    client, store, *_ = env
    r = client.get("/api/v1/telemetry", headers=auth_header(token(**kwargs)))
    assert r.status_code == 401 and r.json()["error"] == error
    assert last_event(store)["action"] == "AgentDenied"


def test_missing_token_is_401(env):
    client, *_ = env
    assert client.get("/api/v1/telemetry").status_code == 401


def test_user_tokens_are_not_accepted(env):
    client, *_ = env
    r = client.get("/api/v1/telemetry", headers=auth_header(token(extra={"scp": "User.Read"})))
    assert r.status_code == 403 and r.json()["error"] == "user_token"


# --- governance checks ------------------------------------------------------------

def test_identity_outside_the_lifecycle_is_refused(env):
    client, *_ = env
    r = client.get("/api/v1/telemetry", headers=auth_header(token(oid="oid-rogue")))
    assert r.status_code == 403 and r.json()["error"] == "not_governed"


def test_suspended_agent_is_refused_while_its_token_is_still_valid(env):
    client, store, directory, _ = env
    tok = token(oid="oid-hermes")
    assert client.get("/api/v1/telemetry", headers=auth_header(tok)).status_code == 200
    directory.entries["oid-hermes"]["accountEnabled"] = False
    directory.entries["oid-hermes"]["notes"] = "Suspended by JML Engine: sponsor E1014 left."
    r = client.get("/api/v1/telemetry", headers=auth_header(tok))
    body = r.json()
    assert r.status_code == 403 and body["error"] == "agent_suspended"
    assert "still valid for" in body["message"] and "sponsor E1014 left" in body["message"]
    assert last_event(store)["user_name"] == "HERMES (AI agent)"


def test_status_check_fails_closed(env):
    client, _, directory, _ = env
    directory.down = True
    r = client.get("/api/v1/telemetry", headers=auth_header(token()))
    assert r.status_code == 503 and r.json()["error"] == "status_unavailable"


def test_missing_role_is_denied_and_logged(env):
    client, store, *_ = env
    r = client.post("/api/v1/commands", headers=auth_header(token()),
                    json={"target": "MO-3 Petrel", "action": "Exit safe mode"})
    assert r.status_code == 403 and r.json()["error"] == "missing_role"
    event = last_event(store)
    assert event["action"] == "AgentDenied" and "missing_role" in event["detail"]


# --- what agents can and can't do --------------------------------------------------

def vega():
    return auth_header(token(oid="oid-vega", roles=("Agent.Telemetry.Read", "Agent.Commands.Propose")))


def test_agent_proposes_but_never_approves(env):
    client, store, *_ = env
    r = client.post("/api/v1/commands", headers=vega(),
                    json={"target": "MO-3 Petrel", "action": "Exit safe mode", "rationale": "Battery recovered to 61%"})
    assert r.status_code == 201
    command_id = r.json()["id"]
    assert store.command(command_id)["proposer_type"] == "agent"
    r = client.post(f"/api/v1/commands/{command_id}/approve", headers=vega())
    assert r.status_code == 403 and r.json()["error"] == "humans_only"
    assert store.command(command_id)["state"] == "Awaiting Flight Director"


def test_agents_never_read_crew_records(env):
    client, *_ = env
    r = client.get("/api/v1/crew", headers=vega())
    assert r.status_code == 403 and r.json()["error"] == "personal_data"


def test_proposals_are_validated(env):
    client, *_ = env
    assert client.post("/api/v1/commands", headers=vega(), json={"target": "MO-9 Nowhere", "action": "Boost"}).status_code == 400
    assert client.post("/api/v1/commands", headers=vega(), content="not json").status_code == 400


# --- humans approve -----------------------------------------------------------------

def sign_in(client, auth, store, user_name, roles, display="Hannah Brooks"):
    store.create({"user_name": user_name, "display_name": display, "department": "Mission Ops"})
    auth.sessions["sid1"] = {"claims": {"preferred_username": user_name, "roles": roles}, "checked": time.time(),
                             "cache": None}
    data = base64.b64encode(json.dumps({"sid": "sid1", "csrf": "csrf-token"}).encode())
    client.cookies.set("mc_session", TimestampSigner("x" * 32).sign(data).decode())


def test_flight_director_approves_an_agent_proposal(env):
    client, store, _, auth = env
    command_id = client.post("/api/v1/commands", headers=vega(),
                             json={"target": "MO-2 Wren", "action": "Trim burn +0.1 m/s"}).json()["id"]
    sign_in(client, auth, store, "hbrooks@lab.test", ["MissionControl.FlightDirector"])
    page = client.get("/").text
    assert command_id in page and "AI agent" in page and "Go</button>" in page
    r = client.post(f"/commands/{command_id}/decide", data={"decision": "approve", "csrf": "csrf-token"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert store.command(command_id)["state"] == "Approved"
    assert store.command(command_id)["decided_by"] == "Hannah Brooks"


def test_decision_needs_csrf_token(env):
    client, store, _, auth = env
    sign_in(client, auth, store, "hbrooks@lab.test", ["MissionControl.FlightDirector"])
    r = client.post("/commands/CMD-311/decide", data={"decision": "approve", "csrf": "forged"})
    assert r.status_code == 400 and store.command("CMD-311")["state"] == "Awaiting Flight Director"


def test_operator_cannot_approve(env):
    client, store, _, auth = env
    sign_in(client, auth, store, "mchen@lab.test", ["MissionControl.Operator"], "Michael Chen")
    assert "Go</button>" not in client.get("/").text
    r = client.post("/commands/CMD-311/decide", data={"decision": "approve", "csrf": "csrf-token"})
    assert r.status_code == 403 and store.command("CMD-311")["state"] == "Awaiting Flight Director"


def test_agents_page_shows_live_status_and_denials(env):
    client, store, directory, auth = env
    client.get("/api/v1/crew", headers=vega())
    directory.entries["oid-hermes"]["accountEnabled"] = False
    directory.entries["oid-hermes"]["notes"] = "Suspended: sponsor E1014 left."
    sign_in(client, auth, store, "hbrooks@lab.test", ["MissionControl.FlightDirector"])
    html = client.get("/agents").text
    assert "HERMES (AI agent)" in html and "Suspended" in html and "sponsor E1014 left" in html
    assert "Some script" not in html            # only lifecycle-governed agents are listed
    assert "personal_data" in html               # VEGA's denied attempt is in the activity log


def test_agents_page_is_flight_directors_only(env):
    client, store, _, auth = env
    sign_in(client, auth, store, "mchen@lab.test", ["MissionControl.Operator"], "Michael Chen")
    assert client.get("/agents").status_code == 403


# --- directory: live lookups are cached briefly, failures surface -----------------

class FakeHttp:
    def __init__(self, status=200, payload=None):
        self.status, self.payload, self.calls = status, payload or {}, 0

    def get(self, url, headers, timeout):
        self.calls += 1
        status, payload = self.status, self.payload

        class R:
            status_code = status
            text = json.dumps(payload)

            def json(self):
                return payload
        return R()


class FakeMsal:
    def acquire_token_for_client(self, scopes):
        return {"access_token": "graph-token"}


def test_directory_caches_then_refreshes():
    settings = Settings(tenant_id=TENANT, client_id=MC_APP, client_secret="s")
    http = FakeHttp(payload=AGENTS["oid-atlas"])
    d = AgentDirectory(settings, ttl=60, app_factory=FakeMsal, http=http)
    assert d.lookup("oid-atlas")["displayName"] == "ATLAS (AI agent)"
    d.lookup("oid-atlas")
    assert http.calls == 1
    d.ttl = 0
    d.lookup("oid-atlas")
    assert http.calls == 2


def test_directory_errors_raise_unavailable():
    settings = Settings(tenant_id=TENANT, client_id=MC_APP, client_secret="s")
    d = AgentDirectory(settings, app_factory=FakeMsal, http=FakeHttp(status=403, payload={"error": "Forbidden"}))
    with pytest.raises(DirectoryUnavailable):
        d.lookup("oid-atlas")
    assert AgentDirectory(settings, app_factory=FakeMsal, http=FakeHttp(status=404)).lookup("x") is None


# --- sign-in fix ----------------------------------------------------------------------

class FakeSignInApp:
    counter = 0

    def initiate_auth_code_flow(self, scopes, redirect_uri, prompt):
        FakeSignInApp.counter += 1
        state = f"state-{FakeSignInApp.counter}"
        return {"auth_uri": f"https://login.test/?state={state}", "state": state, "code_verifier": "v"}

    def acquire_token_by_auth_code_flow(self, flow, params):
        return {"id_token_claims": {"preferred_username": "hbrooks@lab.test", "roles": ["MissionControl.Viewer"]}}


def make_auth(tmp_path):
    settings = Settings(tenant_id=TENANT, client_id=MC_APP, client_secret="s", public_base_url="https://lab.test")
    store = Store(str(tmp_path / "s.db"))
    return Auth(settings, store, app_factory=lambda cache=None: FakeSignInApp()), store, settings


def test_double_click_leaves_both_sign_ins_valid(tmp_path):
    auth, *_ = make_auth(tmp_path)
    first = auth.begin("browser-1").split("state=")[1]
    auth.begin("browser-1")
    sid, claims = auth.complete("browser-1", {"state": first, "code": "c"})
    assert sid and claims["preferred_username"] == "hbrooks@lab.test"


def test_sign_in_survives_an_app_restart(tmp_path):
    auth, store, settings = make_auth(tmp_path)
    state = auth.begin("browser-1").split("state=")[1]
    restarted = Auth(settings, Store(str(tmp_path / "s.db")), app_factory=lambda cache=None: FakeSignInApp())
    sid, _ = restarted.complete("browser-1", {"state": state, "code": "c"})
    assert restarted.claims(sid)


def test_callback_from_another_browser_is_refused(tmp_path):
    auth, *_ = make_auth(tmp_path)
    state = auth.begin("victim-browser").split("state=")[1]
    with pytest.raises(ValueError, match="different browser"):
        auth.complete("attacker-browser", {"state": state, "code": "c"})


def test_a_sign_in_can_only_be_completed_once(tmp_path):
    auth, *_ = make_auth(tmp_path)
    state = auth.begin("browser-1").split("state=")[1]
    auth.complete("browser-1", {"state": state, "code": "c"})
    with pytest.raises(ValueError, match="already used"):
        auth.complete("browser-1", {"state": state, "code": "c"})


def test_entra_errors_are_shown(tmp_path):
    auth, *_ = make_auth(tmp_path)
    with pytest.raises(ValueError, match="AADSTS50105"):
        auth.complete("b", {"error": "access_denied", "error_description": "AADSTS50105: not assigned"})


# --- provisioning log noise -------------------------------------------------------------

def test_no_change_updates_are_not_logged(env):
    client, store, *_ = env
    headers = {"Authorization": "Bearer " + "t" * 48}
    uid = client.post("/scim/v2/Users", headers=headers, json={"userName": "a@lab.test", "active": True}).json()["id"]
    before = len(store.events(100))
    client.patch(f"/scim/v2/Users/{uid}", headers=headers,
                 json={"Operations": [{"op": "replace", "path": "active", "value": "True"}]})
    assert len(store.events(100)) == before
    client.patch(f"/scim/v2/Users/{uid}", headers=headers,
                 json={"Operations": [{"op": "replace", "path": "active", "value": "False"}]})
    assert store.events(1)[0]["detail"] == "Deprovisioned (active=false)"
