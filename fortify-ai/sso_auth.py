"""
SSO (Scramble ID / EFX SSO) integration for FastAPI.

Implements the steps from the "FUFD: Scramble ID integration" page, adapted
from Flask to FastAPI (Flask's before_request -> FastAPI middleware):
  1. Config from env / Secret Manager
  2. JWT validation via JWKS (RS256, iss/aud/exp, cached keys)
  3. Auth middleware on every request
  4. /auth/config, /auth/token, /auth/refresh, /me, /logout
  5. SSO group -> app role mapping

Use in BOTH api_server.py (FortifyAI :8001) and api.py (SonarAI :8000):

    from sso_auth import init_sso, require_role, current_user
    app = FastAPI(...)
    init_sso(app)

    @app.post("/pipeline/live", dependencies=[Depends(require_role("admin"))])
    def run_live(..., user: dict = Depends(current_user)): ...

pip install "pyjwt[crypto]" requests

Local development: set SSO_ENABLED=false to skip token checks. Every request
then runs as a fixed dev user with all roles, and the EFX_SSO_* variables are
not required. Never set this in a deployed environment.

Login only, no role checks: set SSO_ENFORCE_ROLES=false. A valid SSO token is
still required (no/invalid token -> 401), but require_role() lets every
signed-in user through, so nobody gets 403. Use this until the SSO team adds a
groups claim to the access token, then remove it (or set it to true).
"""

import os
import requests
import jwt
from jwt import PyJWKClient
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ── Step 1: Configuration ────────────────────────────────────────────────────
SSO_ENABLED = os.environ.get("SSO_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")
_env = (lambda k: os.environ[k]) if SSO_ENABLED else (lambda k: os.environ.get(k, ""))

ISSUER        = _env("EFX_SSO_ISSUER")
CLIENT_ID     = _env("EFX_SSO_CLIENT_ID")
CLIENT_SECRET = _env("EFX_SSO_CLIENT_SECRET")   # from Secret Manager
REDIRECT_URI  = _env("EFX_SSO_REDIRECT_URI")
JWKS_URL      = _env("EFX_SSO_JWKS_URL")
TOKEN_URL     = _env("EFX_SSO_TOKEN_URL")
# Not in the page's env list but needed by /auth/config — ask the SSO team
AUTH_URL      = os.environ.get("EFX_SSO_AUTH_URL", "")
LOGOUT_URL    = os.environ.get("EFX_SSO_LOGOUT_URL", "")
GROUPS_CLAIM  = os.environ.get("EFX_SSO_GROUPS_CLAIM", "groups")
# false = authentication only; role checks are skipped (see module docstring)
ENFORCE_ROLES = os.environ.get("SSO_ENFORCE_ROLES", "true").strip().lower() not in ("0", "false", "no", "off")

PUBLIC_PATHS = {"/auth/config", "/auth/token", "/auth/refresh",
                "/health", "/api/health",   # liveness probes (FortifyAI, SonarAI)
                "/docs", "/openapi.json"}

# ── Step 5: Role mapping ─────────────────────────────────────────────────────
GROUP_ROLE_MAP = {
    "APP_USERS":    "user",
    "APP_ADMINS":   "admin",
    "APP_DATA_GOV": "dataGovernance",
}

# ── Step 2: Token validation service ─────────────────────────────────────────
_jwks = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=3600) if SSO_ENABLED else None

_DEV_USER = {"id": "dev", "email": "dev@localhost", "first_name": "Dev", "last_name": "User",
             "groups": list(GROUP_ROLE_MAP), "roles": sorted(set(GROUP_ROLE_MAP.values()))}


def validate_token(token: str) -> dict:
    """Verify RS256 signature + iss, aud, exp. Raises jwt exceptions on failure."""
    key = _jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token, key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=CLIENT_ID,
        options={"require": ["exp", "iss", "aud", "sub"]},
        leeway=30,
    )


def _user_from_claims(c: dict) -> dict:
    groups = c.get(GROUPS_CLAIM) or []
    if isinstance(groups, str):
        groups = [groups]
    return {
        "id": c["sub"],
        "email": c.get("email"),
        "first_name": c.get("given_name"),
        "last_name": c.get("family_name"),
        "groups": groups,
        "roles": sorted({GROUP_ROLE_MAP[g] for g in groups if g in GROUP_ROLE_MAP}),
    }


# ── Dependencies for routes ──────────────────────────────────────────────────
def current_user(request: Request) -> dict:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "not_authenticated")
    return user


def require_role(*roles: str):
    def checker(user: dict = Depends(current_user)) -> dict:
        if ENFORCE_ROLES and not set(roles) & set(user["roles"]):
            raise HTTPException(403, "forbidden")
        return user
    return checker


# ── Step 4: Endpoints ────────────────────────────────────────────────────────
router = APIRouter()


class CodeIn(BaseModel):
    code: str
    code_verifier: str | None = None   # if the frontend uses PKCE


class RefreshIn(BaseModel):
    refresh_token: str


@router.get("/auth/config")
def auth_config():
    return {"authorization_url": AUTH_URL, "logout_url": LOGOUT_URL,
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "issuer": ISSUER}


def _token_call(data: dict) -> dict:
    r = requests.post(TOKEN_URL, data=data, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)
    if r.status_code != 200:
        raise HTTPException(401, f"sso_token_error: {r.text}")
    b = r.json()
    return {"access_token": b.get("access_token"),
            "id_token": b.get("id_token"),   # page warns: confirm it's returned on refresh
            "refresh_token": b.get("refresh_token"),
            "expires_in": b.get("expires_in")}


@router.post("/auth/token")
def auth_token(body: CodeIn):
    data = {"grant_type": "authorization_code", "code": body.code,
            "redirect_uri": REDIRECT_URI}
    if body.code_verifier:
        data["code_verifier"] = body.code_verifier
    return _token_call(data)


@router.post("/auth/refresh")
def auth_refresh(body: RefreshIn):
    return _token_call({"grant_type": "refresh_token",
                        "refresh_token": body.refresh_token})


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return user


@router.post("/logout")
def logout(user: dict = Depends(current_user)):
    # Stateless JWTs: frontend clears tokens and redirects to LOGOUT_URL.
    return {"ok": True, "logout_url": LOGOUT_URL}


# ── Step 3: Middleware (Flask before_request equivalent) ─────────────────────
def init_sso(app: FastAPI) -> None:
    if not SSO_ENABLED:
        print("[SSO] WARNING: SSO_ENABLED=false — all requests run as an unauthenticated dev admin")
    elif not ENFORCE_ROLES:
        print("[SSO] WARNING: SSO_ENFORCE_ROLES=false — login required, but role checks are OFF")
    app.include_router(router)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if not SSO_ENABLED:
            request.state.user = _DEV_USER
            return await call_next(request)
        if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return JSONResponse({"error": "missing_token"}, status_code=401)
        try:
            claims = await run_in_threadpool(validate_token, header[7:])
        except jwt.ExpiredSignatureError:
            return JSONResponse({"error": "token_expired"}, status_code=401)
        except jwt.PyJWTError as e:
            return JSONResponse({"error": "invalid_token", "detail": str(e)},
                                status_code=401)
        request.state.user = _user_from_claims(claims)
        return await call_next(request)