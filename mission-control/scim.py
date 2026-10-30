"""SCIM 2.0 (RFC 7643/7644) Users endpoint, built for Microsoft Entra ID provisioning.

Entra calls this to create, update, deactivate and delete Mission Control accounts as
users are assigned to (or removed from) the app's groups in Entra.
"""
import hmac
import re

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from store import Conflict

CORE = "urn:ietf:params:scim:schemas:core:2.0:User"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
MEDIA = "application/scim+json"

FILTER_RE = re.compile(r'^\s*(\w+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$', re.IGNORECASE)
FILTER_COLUMNS = {"username": "user_name", "externalid": "external_id", "id": "id"}

# SCIM attribute path (lower-case) -> store column
PATHS = {
    "username": "user_name",
    "externalid": "external_id",
    "active": "active",
    "displayname": "display_name",
    "name.givenname": "given_name",
    "name.familyname": "family_name",
    'emails[type eq "work"].value': "email",
    "emails": "email",
    "title": "title",
    f"{ENTERPRISE}:department".lower(): "department",
}


class ScimError(Exception):
    def __init__(self, status, detail, scim_type=None):
        self.status, self.detail, self.scim_type = status, detail, scim_type


def scim_json(body, status=200):
    return JSONResponse(body, status_code=status, media_type=MEDIA)


def error_response(err):
    body = {"schemas": [ERROR], "status": str(err.status), "detail": err.detail}
    if err.scim_type:
        body["scimType"] = err.scim_type
    return scim_json(body, err.status)


def to_bool(value):
    # Entra has historically sent "True"/"False" as strings in PATCH requests.
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    raise ScimError(400, f"Invalid boolean: {value!r}", "invalidValue")


def unwrap(value):
    """[{"value": "x", ...}] -> "x"; anything else unchanged."""
    if isinstance(value, list):
        if not value:
            return None
        primary = next((v for v in value if isinstance(v, dict) and v.get("primary")), value[0])
        return primary.get("value") if isinstance(primary, dict) else primary
    return value


def apply_path(fields, path, value):
    column = PATHS.get(path.strip().lower())
    if column is None:
        return False  # attribute Mission Control doesn't store: accept and ignore
    value = unwrap(value)
    fields[column] = to_bool(value) if column == "active" else value
    return True


def flatten(resource):
    """A SCIM User body (or a PATCH value object) -> {path: value}."""
    flat = {}
    for key, value in resource.items():
        if key in ("schemas", "id", "meta"):
            continue
        if key == "name" and isinstance(value, dict):
            for sub, v in value.items():
                flat[f"name.{sub}"] = v
        elif key == ENTERPRISE and isinstance(value, dict):
            for sub, v in value.items():
                flat[f"{ENTERPRISE}:{sub}"] = v
        else:
            flat[key] = value
    return flat


def fields_from(resource):
    fields = {}
    for path, value in flatten(resource).items():
        apply_path(fields, path, value)
    return fields


def to_resource(row, base_url):
    resource = {
        "schemas": [CORE, ENTERPRISE],
        "id": row["id"],
        "externalId": row["external_id"],
        "userName": row["user_name"],
        "active": bool(row["active"]),
        "displayName": row["display_name"],
        "name": {"givenName": row["given_name"], "familyName": row["family_name"]},
        "title": row["title"],
        ENTERPRISE: {"department": row["department"]},
        "meta": {
            "resourceType": "User",
            "created": row["created"],
            "lastModified": row["last_modified"],
            "location": f"{base_url}/Users/{row['id']}",
        },
    }
    if row["email"]:
        resource["emails"] = [{"value": row["email"], "type": "work", "primary": True}]
    return resource


def describe(before, after):
    if before["active"] and not after["active"]:
        return "Deprovisioned (active=false)"
    if not before["active"] and after["active"]:
        return "Reactivated (active=true)"
    changed = [k for k in after if k not in ("last_modified", "created") and before.get(k) != after.get(k)]
    return "Updated " + ", ".join(changed) if changed else "No change"


def build_router(settings, store):
    router = APIRouter(prefix="/scim/v2")

    async def require_token(request: Request):
        header = request.headers.get("authorization", "")
        token = header[7:] if header.lower().startswith("bearer ") else ""
        if not token or not hmac.compare_digest(token, settings.scim_token):
            raise ScimError(401, "Missing or invalid bearer token")

    def base(request):
        return f"{settings.public_base_url or str(request.base_url).rstrip('/')}/scim/v2"

    async def body_of(request):
        try:
            body = await request.json()
        except Exception:
            raise ScimError(400, "Body must be JSON", "invalidSyntax")
        if not isinstance(body, dict):
            raise ScimError(400, "Body must be a JSON object", "invalidSyntax")
        return body

    def load(user_id):
        row = store.get(user_id)
        if not row:
            raise ScimError(404, f"User {user_id} not found")
        return row

    auth = [Depends(require_token)]

    @router.get("/ServiceProviderConfig", dependencies=auth)
    async def service_provider_config():
        return scim_json({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token",
                                       "description": "Long-lived bearer token from Entra provisioning"}],
        })

    @router.get("/Users", dependencies=auth)
    async def list_users(request: Request, filter: str = None, startIndex: int = 1, count: int = 100):
        if filter:
            match = FILTER_RE.match(filter)
            column = FILTER_COLUMNS.get(match.group(1).lower()) if match else None
            if not column:
                raise ScimError(400, f"Unsupported filter: {filter}", "invalidFilter")
            rows = store.find(column, match.group(2).replace('\\"', '"'))
        else:
            rows = store.all()
        start = max(startIndex, 1)
        page = rows[start - 1:start - 1 + max(count, 0)]
        return scim_json({"schemas": [LIST], "totalResults": len(rows), "startIndex": start,
                          "itemsPerPage": len(page), "Resources": [to_resource(r, base(request)) for r in page]})

    @router.post("/Users", dependencies=auth)
    async def create_user(request: Request):
        fields = fields_from(await body_of(request))
        if not fields.get("user_name"):
            raise ScimError(400, "userName is required", "invalidValue")
        try:
            row = store.create(fields)
        except Conflict:
            raise ScimError(409, f"userName {fields['user_name']} already exists", "uniqueness")
        store.log("Create", row["user_name"], f"{row['department'] or ''} {row['title'] or ''}".strip())
        return scim_json(to_resource(row, base(request)), 201)

    @router.get("/Users/{user_id}", dependencies=auth)
    async def get_user(request: Request, user_id: str):
        return scim_json(to_resource(load(user_id), base(request)))

    @router.put("/Users/{user_id}", dependencies=auth)
    async def replace_user(request: Request, user_id: str):
        before = load(user_id)
        try:
            after = store.update(user_id, fields_from(await body_of(request)))
        except Conflict as exc:
            raise ScimError(409, f"userName {exc} already exists", "uniqueness")
        change = describe(before, after)
        if change != "No change":   # Entra re-checks users constantly; only real changes are worth logging
            store.log("Replace", after["user_name"], change)
        return scim_json(to_resource(after, base(request)))

    @router.patch("/Users/{user_id}", dependencies=auth)
    async def patch_user(request: Request, user_id: str):
        before = load(user_id)
        body = await body_of(request)
        operations = body.get("Operations") or body.get("operations")
        if not isinstance(operations, list):
            raise ScimError(400, "PATCH body needs an Operations list", "invalidSyntax")
        fields = {}
        for operation in operations:
            op = str(operation.get("op", "")).lower()
            path, value = operation.get("path"), operation.get("value")
            if op not in ("add", "replace", "remove"):
                raise ScimError(400, f"Unsupported op: {operation.get('op')}", "invalidSyntax")
            if op == "remove":
                if path and PATHS.get(path.strip().lower()) not in (None, "active", "user_name"):
                    fields[PATHS[path.strip().lower()]] = None
            elif path:
                apply_path(fields, path, value)
            elif isinstance(value, dict):
                for sub_path, sub_value in flatten(value).items():
                    apply_path(fields, sub_path, sub_value)
            else:
                raise ScimError(400, "Operation without a path needs an object value", "invalidSyntax")
        try:
            after = store.update(user_id, fields)
        except Conflict as exc:
            raise ScimError(409, f"userName {exc} already exists", "uniqueness")
        change = describe(before, after)
        if change != "No change":
            store.log("Update", after["user_name"], change)
        return scim_json(to_resource(after, base(request)))

    @router.delete("/Users/{user_id}", dependencies=auth)
    async def delete_user(user_id: str):
        row = load(user_id)
        store.delete(user_id)
        store.log("Delete", row["user_name"], "Account deleted")
        return Response(status_code=204)

    # Group provisioning is not used: access is driven by group assignment in Entra.
    @router.get("/Groups", dependencies=auth)
    async def list_groups():
        return scim_json({"schemas": [LIST], "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": []})

    return router
