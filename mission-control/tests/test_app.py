"""Tests for the SCIM endpoint and the access checks. No Entra tenant needed."""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["MISSIONCONTROL_NO_AUTOAPP"] = "1"
from app import Settings, create_app  # noqa: E402
from store import Store  # noqa: E402

TOKEN = "t" * 48
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/scim+json"}
ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


class FakeAuth:
    """Stands in for MSAL: a signed-in session whose validity the test controls."""
    def __init__(self):
        self.sessions, self.valid = {}, True

    def claims(self, sid):
        return self.sessions.get(sid)

    def still_valid(self, sid):
        return self.valid

    def seconds_since_check(self, sid):
        return 5

    def end(self, sid):
        self.sessions.pop(sid, None)

    def logout_url(self):
        return "https://login.example/logout"


@pytest.fixture
def env(tmp_path):
    settings = Settings(tenant_id="t", client_id="c", client_secret="s", public_base_url="https://lab.test",
                        scim_token=TOKEN, session_secret="x" * 32, cookie_secure=False)
    store, auth = Store(str(tmp_path / "t.db")), FakeAuth()
    client = TestClient(create_app(settings, store=store, auth=auth, validator=object(), directory=object()))
    return client, store, auth


def scim_user(user_name="emccarthy@lab.test", dept="Mission Ops", title="Flight Controller"):
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", ENT], "userName": user_name,
            "externalId": user_name.split("@")[0], "active": True, "displayName": "Erin McCarthy",
            "name": {"givenName": "Erin", "familyName": "McCarthy"}, "title": title,
            "emails": [{"value": user_name, "type": "work", "primary": True}], ENT: {"department": dept}}


def sign_in(client, auth, user_name, roles):
    """Puts a fake signed-in session into the cookie the app reads."""
    auth.sessions["sid1"] = {"preferred_username": user_name, "roles": roles}
    from itsdangerous import TimestampSigner
    import base64, json
    signer = TimestampSigner("x" * 32)
    data = base64.b64encode(json.dumps({"sid": "sid1", "csrf": "csrf-token"}).encode())
    client.cookies.set("mc_session", signer.sign(data).decode())


# --- SCIM -------------------------------------------------------------------

def test_rejects_missing_or_wrong_token(env):
    client, _, _ = env
    assert client.get("/scim/v2/Users").status_code == 401
    assert client.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_entra_connection_test_gets_empty_list(env):
    client, _, _ = env
    r = client.get('/scim/v2/Users?filter=userName eq "a1b2c3"', headers=HEADERS)
    assert r.status_code == 200 and r.json()["totalResults"] == 0


def test_create_then_filter_by_username(env):
    client, _, _ = env
    r = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user())
    assert r.status_code == 201
    body = r.json()
    assert body["id"] and body[ENT]["department"] == "Mission Ops"
    found = client.get('/scim/v2/Users?filter=userName eq "EMCCARTHY@lab.test"', headers=HEADERS).json()
    assert found["totalResults"] == 1


def test_duplicate_username_is_409(env):
    client, _, _ = env
    client.post("/scim/v2/Users", headers=HEADERS, json=scim_user())
    r = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user())
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"


def test_patch_active_false_as_string_deprovisions(env):
    client, store, _ = env
    uid = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user()).json()["id"]
    patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}
    r = client.patch(f"/scim/v2/Users/{uid}", headers=HEADERS, json=patch)
    assert r.status_code == 200 and r.json()["active"] is False
    assert store.events(1)[0]["detail"] == "Deprovisioned (active=false)"


def test_patch_without_path_and_enterprise_department(env):
    client, _, _ = env
    uid = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user()).json()["id"]
    patch = {"Operations": [
        {"op": "replace", "value": {"title": "Accountant", f"{ENT}:department": "Finance"}},
        {"op": "replace", "path": "name.familyName", "value": "McCarthy-Lee"}]}
    body = client.patch(f"/scim/v2/Users/{uid}", headers=HEADERS, json=patch).json()
    assert body["title"] == "Accountant" and body[ENT]["department"] == "Finance"
    assert body["name"]["familyName"] == "McCarthy-Lee"


def test_unknown_attributes_are_ignored_not_rejected(env):
    client, _, _ = env
    uid = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user()).json()["id"]
    patch = {"Operations": [{"op": "add", "path": "preferredLanguage", "value": "en-US"}]}
    assert client.patch(f"/scim/v2/Users/{uid}", headers=HEADERS, json=patch).status_code == 200


def test_delete_and_404(env):
    client, _, _ = env
    uid = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user()).json()["id"]
    assert client.delete(f"/scim/v2/Users/{uid}", headers=HEADERS).status_code == 204
    r = client.get(f"/scim/v2/Users/{uid}", headers=HEADERS)
    assert r.status_code == 404 and r.json()["status"] == "404"


def test_bad_filter_is_400(env):
    client, _, _ = env
    r = client.get('/scim/v2/Users?filter=title co "x"', headers=HEADERS)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidFilter"


# --- Access checks ----------------------------------------------------------

def test_signed_out_sees_sign_in_page(env):
    client, _, _ = env
    r = client.get("/")
    assert r.status_code == 200 and "Sign in with Microsoft" in r.text


def test_viewer_sees_fleet_but_not_command_queue(env):
    client, _, auth = env
    client.post("/scim/v2/Users", headers=HEADERS, json=scim_user("enguyen@lab.test", "Flight Software", "Engineer"))
    sign_in(client, auth, "enguyen@lab.test", ["MissionControl.Viewer"])
    r = client.get("/")
    assert r.status_code == 200 and "Kestrel" in r.text and "CMD-311" not in r.text


def test_operator_sees_command_queue(env):
    client, _, auth = env
    client.post("/scim/v2/Users", headers=HEADERS, json=scim_user())
    sign_in(client, auth, "emccarthy@lab.test", ["MissionControl.Operator"])
    r = client.get("/")
    assert "CMD-311" in r.text and "waiting for your go" not in r.text
    assert "Provisioning activity" not in client.get("/crew").text


def test_flight_director_gets_approvals_and_provisioning_log(env):
    client, _, auth = env
    client.post("/scim/v2/Users", headers=HEADERS, json=scim_user("hbrooks@lab.test", "Mission Ops", "Flight Director"))
    sign_in(client, auth, "hbrooks@lab.test", ["MissionControl.Operator", "MissionControl.FlightDirector"])
    assert "waiting for your go" in client.get("/").text
    assert "Provisioning activity" in client.get("/crew").text


def test_deprovisioned_user_is_blocked_mid_session(env):
    client, _, auth = env
    uid = client.post("/scim/v2/Users", headers=HEADERS, json=scim_user()).json()["id"]
    sign_in(client, auth, "emccarthy@lab.test", ["MissionControl.Operator"])
    assert client.get("/").status_code == 200
    client.patch(f"/scim/v2/Users/{uid}", headers=HEADERS,
                 json={"Operations": [{"op": "replace", "path": "active", "value": False}]})
    r = client.get("/")
    assert r.status_code == 403 and "Access removed" in r.text


def test_revoked_session_is_kicked_out(env):
    client, _, auth = env
    client.post("/scim/v2/Users", headers=HEADERS, json=scim_user())
    sign_in(client, auth, "emccarthy@lab.test", ["MissionControl.Operator"])
    auth.valid = False
    r = client.get("/")
    assert r.status_code == 403 and "session was ended" in r.text


def test_signed_in_but_not_provisioned_is_blocked(env):
    client, _, auth = env
    sign_in(client, auth, "stranger@lab.test", ["MissionControl.Operator"])
    assert client.get("/").status_code == 403


# --- Session re-verification against Entra (MSAL stubbed) --------------------

class FakeMsalApp:
    def __init__(self, result):
        self.result = result

    def get_accounts(self):
        return [{"home_account_id": "x"}]

    def acquire_token_silent_with_error(self, scopes, account, force_refresh):
        return self.result


def make_auth(result, every=60):
    from auth import Auth
    settings = Settings(revalidate_seconds=every)
    a = Auth(settings, None, app_factory=lambda cache=None: FakeMsalApp(result))
    a.sessions["s"] = {"cache": None, "claims": {"preferred_username": "u"}, "checked": 0}
    return a


def test_revoked_refresh_token_ends_session():
    assert make_auth({"error": "invalid_grant"}).still_valid("s") is False


def test_healthy_refresh_keeps_session():
    a = make_auth({"access_token": "ok"})
    assert a.still_valid("s") is True and a.seconds_since_check("s") == 0


def test_network_blip_does_not_kick_user_out():
    assert make_auth({"error": "temporarily_unavailable"}).still_valid("s") is True
