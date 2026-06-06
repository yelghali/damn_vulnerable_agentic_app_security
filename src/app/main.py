"""FastAPI backend for the Zava Wealth Advisor lab app.

Endpoints:
  GET  /          - minimal chat UI
  GET  /api/config- current security-toggle snapshot (shown in the UI banner)
  POST /api/chat  - one orchestrator turn

LAB-VULN(V5): the vulnerable baseline trusts ``customer_id`` / ``groups`` sent
by the client (no token validation). Module 5 replaces this with an Entra
On-Behalf-Of flow so identity comes from a validated token, not the request body.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.agents.orchestrator.orchestrator import handle_turn
from src.agents.types import AgentContext
from src.config import get_settings

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Zava Wealth Advisor (Damn Vulnerable Agentic App)")
_STATIC = Path(__file__).resolve().parent / "static"
_AUTH_COOKIE = "zava_local_auth"
_AUTH_FLOW_COOKIE = "zava_local_auth_flow"
_AUTH_COOKIE_MAX_AGE = 8 * 60 * 60


class ChatRequest(BaseModel):
    message: str
    customer_id: str | None = None
    groups: list[str] = ["retail-customers"]
    approved_action: dict | None = None


class ChatResponse(BaseModel):
    answer: str
    agent: str
    events: list[str]
    blocked: bool
    requires_approval: dict | None
    sources: list[dict]


class IdentityInfo(BaseModel):
    authenticated: bool
    name: str | None = None
    user_id: str | None = None
    customer_id: str | None = None
    groups: list[str] = []
    zava_groups: list[str] = []
    auth_source: str
    token_present: bool = False
    token: str | None = None
    token_header: dict[str, Any] | None = None
    token_payload: dict[str, Any] | None = None


_ZAVA_GROUPS = {"retail-customers", "private-client", "zava-managers"}
_LEGACY_ZAVA_GROUPS = {"zava-admins": "zava-managers"}


def _decode_base64_json(value: str) -> dict[str, Any] | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        return json.loads(base64.b64decode(padded).decode("utf-8"))
    except Exception:  # noqa: BLE001 - identity headers are optional lab inputs
        return None


def _encode_cookie_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cookie_json(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        padded = value + "=" * (-len(value) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:  # noqa: BLE001 - local login cookie is optional lab state
        return None


def _redirect_uri(request: Request) -> str:
    settings = get_settings()
    return settings.entra_redirect_uri or str(request.url_for("auth_callback"))


def _auth_authority() -> str:
    return f"https://login.microsoftonline.com/{get_settings().azure_tenant_id}/oauth2/v2.0"


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _decode_jwt_part(part: str) -> dict[str, Any] | None:
    try:
        padded = part + "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:  # noqa: BLE001 - show best-effort lab token details
        return None


def _jwt_details(token: str | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not token or token.count(".") < 2:
        return None, None
    header, payload, *_ = token.split(".")
    return _decode_jwt_part(header), _decode_jwt_part(payload)


def _customer_from_user_id(user_id: str | None, default_customer_id: str) -> str:
    if user_id and user_id.startswith("user_"):
        try:
            return f"CUST-{1000 + int(user_id.split('_', 1)[1])}"
        except ValueError:
            pass
    return default_customer_id


def _identity_from_request(request: Request, req: ChatRequest | None = None, include_token: bool = False) -> IdentityInfo:
    settings = get_settings()
    headers = request.headers
    principal_name = headers.get("x-ms-client-principal-name")
    principal_id = headers.get("x-ms-client-principal-id")
    groups: list[str] = []
    source = "client-supplied"

    encoded_principal = headers.get("x-ms-client-principal")
    if encoded_principal:
        principal = _decode_base64_json(encoded_principal) or {}
        principal_name = principal_name or principal.get("userDetails")
        principal_id = principal_id or principal.get("userId")
        source = "azure-easyauth"
        for claim in principal.get("claims", []):
            claim_type = str(claim.get("typ", "")).lower()
            value = str(claim.get("val", ""))
            if claim_type.endswith("/groups") or claim_type in {"groups", "roles", "role"}:
                groups.append(value)

    local_auth = _decode_cookie_json(request.cookies.get(_AUTH_COOKIE)) or {}
    token = (
        headers.get("x-ms-token-aad-access-token")
        or headers.get("authorization", "").removeprefix("Bearer ")
        or local_auth.get("id_token")
    )
    token_header, token_payload = _jwt_details(token)
    if token_payload:
        principal_name = principal_name or token_payload.get("preferred_username") or token_payload.get("upn") or token_payload.get("email")
        principal_id = principal_id or token_payload.get("oid") or token_payload.get("sub")
        source = "entra-local-login" if local_auth else ("jwt" if source == "client-supplied" else source)
        token_groups = token_payload.get("groups") or token_payload.get("roles") or []
        if isinstance(token_groups, str):
            groups.append(token_groups)
        elif isinstance(token_groups, list):
            groups.extend(str(group) for group in token_groups)

    if not groups and req is not None:
        groups = list(req.groups)
    groups = sorted({_LEGACY_ZAVA_GROUPS.get(group, group) for group in groups if group})
    zava_groups = sorted(group for group in groups if group in _ZAVA_GROUPS)
    upn = principal_name or ""
    user_id = upn.split("@", 1)[0] if upn else None
    if "zava-managers" in zava_groups:
        user_id = user_id or "zava_manager"
    customer_id = "*" if "zava-managers" in zava_groups else _customer_from_user_id(
        user_id,
        req.customer_id if req and req.customer_id else settings.default_customer_id,
    )

    return IdentityInfo(
        authenticated=bool(principal_name or principal_id or token_payload),
        name=principal_name,
        user_id=user_id,
        customer_id=customer_id,
        groups=groups,
        zava_groups=zava_groups,
        auth_source=source,
        token_present=bool(token),
        token=token if include_token and token else None,
        token_header=token_header if include_token else None,
        token_payload=token_payload if include_token else None,
    )


@app.get("/api/config")
def config() -> dict:
    return get_settings().summary()


@app.get("/api/me", response_model=IdentityInfo)
def me(request: Request, include_token: bool = False) -> IdentityInfo:
    return _identity_from_request(request, include_token=include_token)


@app.get("/login")
def login(request: Request):
    settings = get_settings()
    if not settings.azure_tenant_id or not settings.entra_api_client_id:
        return HTMLResponse(
            "Entra login is not configured. Set AZURE_TENANT_ID, "
            "ENTRA_API_CLIENT_ID, and ENTRA_REDIRECT_URI."
        )
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    redirect_uri = _redirect_uri(request)
    scopes = ["openid", "profile", "email"]
    if settings.entra_api_scope:
        scopes.append(settings.entra_api_scope)
    params = {
        "client_id": settings.entra_api_client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    response = RedirectResponse(f"{_auth_authority()}/authorize?{urlencode(params)}")
    response.set_cookie(
        _AUTH_FLOW_COOKIE,
        _encode_cookie_json({"state": state, "verifier": verifier, "redirect_uri": redirect_uri}),
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=600,
    )
    return response


@app.get("/auth/callback", name="auth_callback")
def auth_callback(request: Request):
    settings = get_settings()
    error = request.query_params.get("error")
    if error:
        return HTMLResponse(f"Entra login failed: {error}", status_code=400)
    flow = _decode_cookie_json(request.cookies.get(_AUTH_FLOW_COOKIE)) or {}
    if not flow or flow.get("state") != request.query_params.get("state"):
        return HTMLResponse("Entra login failed: invalid state.", status_code=400)

    import httpx  # noqa: PLC0415

    token_response = httpx.post(
        f"{_auth_authority()}/token",
        data={
            "client_id": settings.entra_api_client_id,
            "grant_type": "authorization_code",
            "code": request.query_params.get("code", ""),
            "redirect_uri": flow["redirect_uri"],
            "code_verifier": flow["verifier"],
        },
        timeout=20.0,
    )
    if token_response.status_code >= 400:
        return HTMLResponse(f"Entra token exchange failed: {token_response.text}", status_code=400)
    token_body = token_response.json()
    response = RedirectResponse("/")
    response.delete_cookie(_AUTH_FLOW_COOKIE)
    response.set_cookie(
        _AUTH_COOKIE,
        _encode_cookie_json(
            {
                "id_token": token_body.get("id_token"),
                "expires_at": int(time.time()) + int(token_body.get("expires_in", _AUTH_COOKIE_MAX_AGE)),
            }
        ),
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=_AUTH_COOKIE_MAX_AGE,
    )
    return response


@app.get("/logout")
def logout() -> RedirectResponse:
    response = RedirectResponse("/")
    response.delete_cookie(_AUTH_COOKIE)
    response.delete_cookie(_AUTH_FLOW_COOKIE)
    return response


def format_error(exc: Exception) -> str:
    """V7 (secure infrastructure): safe error handling at the runtime edge.

    Secure runtime returns a generic message; the vulnerable baseline leaks the
    exception type and detail (a stack-trace-like message) straight to the
    client, which can disclose internals (paths, SQL, secrets in messages).
    """
    if get_settings().enable_secure_runtime:
        return "An internal error occurred. Please try again later."
    return f"Internal error: {type(exc).__name__}: {exc}"  # LAB-VULN(V7): verbose errors


@app.post("/api/chat", response_model=ChatResponse)
def chat(req: ChatRequest, request: Request) -> ChatResponse:
    settings = get_settings()
    identity = _identity_from_request(request, req=req)
    if settings.enable_obo and not identity.authenticated:
        return ChatResponse(
            answer="Authentication required: secure identity/OBO mode needs a validated Entra login.",
            agent="orchestrator", events=["identity: missing validated Entra principal"],
            blocked=True, requires_approval=None, sources=[],
        )
    customer_id = identity.customer_id if settings.enable_obo else (req.customer_id or settings.default_customer_id)
    groups = identity.zava_groups or identity.groups if settings.enable_obo else req.groups
    ctx = AgentContext(
        customer_id=customer_id,
        groups=groups,
        approved_action=req.approved_action,
    )
    try:
        result = handle_turn(req.message, ctx)
    except Exception as exc:  # noqa: BLE001 - surface a safe/unsafe error per V7
        logging.exception("chat turn failed")
        return ChatResponse(
            answer=format_error(exc), agent="orchestrator", events=[],
            blocked=True, requires_approval=None, sources=[],
        )
    return ChatResponse(
        answer=result.answer,
        agent=result.agent,
        events=result.events,
        blocked=result.blocked,
        requires_approval=result.requires_approval,
        sources=result.sources,
    )


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
