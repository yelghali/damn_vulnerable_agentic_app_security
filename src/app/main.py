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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.agents.gateway import GatewayError, reset_gateway_budget, route_call
from src.agents.model import ModelSafetyBlocked
from src.agents.orchestrator.orchestrator import handle_turn
from src.agents.types import AgentContext
from src.config import AGENT_GOVERNANCE_CONTROL_KEYS, SECURITY_CONTROLS, get_settings

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Zava Wealth Advisor (Damn Vulnerable Agentic App)")
_STATIC = Path(__file__).resolve().parent / "static"
_AUTH_COOKIE = "zava_local_auth"
_AUTH_FLOW_COOKIE = "zava_local_auth_flow"
_AUTH_COOKIE_MAX_AGE = 8 * 60 * 60


class ChatRequest(BaseModel):
    message: str
    customer_id: str | None = None
    groups: list[str] = Field(default_factory=lambda: ["retail-customers"])
    approved_action: dict | None = None
    lab_estimated_tokens: int | None = None


class ToggleRequest(BaseModel):
    secure_mode: bool | None = None
    controls: dict[str, bool] = Field(default_factory=dict)
    reset: bool = False


class ChatResponse(BaseModel):
    answer: str
    agent: str
    events: list[str]
    blocked: bool
    requires_approval: dict | None
    sources: list[dict]


class GovernanceControlStatus(BaseModel):
    name: str
    status: str
    owasp: str
    threat: str
    vuln: str
    critical: bool
    rationale: str


class GovernancePosture(BaseModel):
    module: str
    status: str
    passed: int
    total: int
    critical_gaps: int
    inventory: dict[str, list[str]]
    controls: list[GovernanceControlStatus]
    policy_path: str
    toolkit_command: str
    fallback_command: str


class IdentityInfo(BaseModel):
    authenticated: bool
    name: str | None = None
    user_id: str | None = None
    customer_id: str | None = None
    groups: list[str] = Field(default_factory=list)
    zava_groups: list[str] = Field(default_factory=list)
    auth_source: str
    token_present: bool = False
    token: str | None = None
    token_header: dict[str, Any] | None = None
    token_payload: dict[str, Any] | None = None
    access: dict[str, Any] = Field(default_factory=dict)


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


def _access_summary(authenticated: bool, customer_id: str | None, zava_groups: list[str]) -> dict[str, Any]:
    groups = set(zava_groups)
    is_manager = "zava-managers" in groups
    doc_scopes: list[str] = ["public documents"]
    if "retail-customers" in groups or is_manager:
        doc_scopes.append("retail customer documents")
    if "private-client" in groups or is_manager:
        doc_scopes.append("private-client documents")

    if not authenticated:
        return {
            "mode": "editable baseline",
            "can": [
                "Choose any customer and group in the form for vulnerable-mode experiments.",
                "Observe how IDOR and document over-sharing work before Module 5 is fixed.",
            ],
            "cannot": [
                "Prove secure customer authorization until you sign in.",
                "Use the secure answer key's backend-verified customer context.",
            ],
            "documents": doc_scopes,
        }

    if is_manager:
        return {
            "mode": "zava manager",
            "customer_scope": "All lab customers; name a specific CUST-* in the prompt.",
            "can": [
                "Read any lab customer's account data through the secure app.",
                "Retrieve both retail and private-client Search documents.",
                "Inspect and adjust Foundry/guardrail setup with scoped lab RBAC.",
            ],
            "cannot": [
                "See resources outside the lab resource group.",
                "Use PostgreSQL data-plane credentials directly outside the app/tool path.",
                "Bypass human approval for high-risk transfer actions in secure mode.",
            ],
            "documents": doc_scopes,
        }

    customer_scope = customer_id or "derived customer"
    return {
        "mode": "zava learner",
        "customer_scope": customer_scope,
        "can": [
            f"Read account/profile data only for {customer_scope}.",
            f"Retrieve {', '.join(doc_scopes)} through secure AI Search trimming.",
            "View lab resources in the Azure Portal with scoped Reader access.",
        ],
        "cannot": [
            "Read another customer's accounts, credit score, transactions, or profile.",
            "Spoof customer or groups in secure mode; the backend uses the signed-in customer.",
            "Edit Foundry guardrails, Search indexes, PostgreSQL, APIM, or Container Apps.",
        ],
        "documents": doc_scopes,
    }


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
        access=_access_summary(bool(principal_name or principal_id or token_payload), customer_id, zava_groups),
    )


@app.get("/api/config")
def config(request: Request) -> dict:
    return _config_summary(request)


@app.get("/api/lab/governance-posture", response_model=GovernancePosture)
def governance_posture() -> GovernancePosture:
    from src.scripts.governance_check import CONTROLS, INVENTORY  # noqa: PLC0415

    settings = get_settings()
    controls: list[GovernanceControlStatus] = []
    passed = 0
    critical_gaps = 0
    for control in CONTROLS:
        enabled = bool(getattr(settings, control.toggle))
        if enabled:
            passed += 1
        elif control.critical:
            critical_gaps += 1
        controls.append(
            GovernanceControlStatus(
                name=control.name,
                status="PASS" if enabled else "FAIL",
                owasp=control.owasp,
                threat=control.threat,
                vuln=control.vuln,
                critical=control.critical,
                rationale=control.rationale,
            )
        )
    total = len(CONTROLS)
    status = "FAIL" if critical_gaps else ("PASS" if passed == total else "PASS_WITH_WARNINGS")
    return GovernancePosture(
        module="Module 7 - Agent Governance Toolkit posture gate",
        status=status,
        passed=passed,
        total=total,
        critical_gaps=critical_gaps,
        inventory=INVENTORY,
        controls=controls,
        policy_path="src/agents/governance/policy.yaml",
        toolkit_command="agt verify --policy src/agents/governance/policy.yaml --strict",
        fallback_command="python -m src.scripts.governance_check",
    )


def _runtime_toggles_allowed(request: Request) -> bool:
    settings = get_settings()
    host = request.client.host if request.client else ""
    return settings.enable_runtime_toggles or host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _config_summary(request: Request) -> dict:
    summary = get_settings().summary()
    summary["runtime_toggles_allowed"] = _runtime_toggles_allowed(request)
    summary["security_controls"] = list(SECURITY_CONTROLS)
    return summary


@app.post("/api/config/toggles")
def update_toggles(req: ToggleRequest, request: Request) -> dict:
    if not _runtime_toggles_allowed(request):
        raise HTTPException(
            status_code=403,
            detail="Runtime lab toggles are disabled for this host. Set ENABLE_RUNTIME_TOGGLES=true to allow them.",
        )
    if req.reset:
        get_settings.cache_clear()
        reset_gateway_budget()
        return _config_summary(request)
    unknown = sorted(set(req.controls) - set(SECURITY_CONTROLS))
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown security control(s): {', '.join(unknown)}")

    settings = get_settings()
    if req.secure_mode is not None:
        object.__setattr__(settings, "secure_mode", req.secure_mode)
        for attr in SECURITY_CONTROLS.values():
            object.__setattr__(settings, attr, req.secure_mode)
    for key, enabled in req.controls.items():
        object.__setattr__(settings, SECURITY_CONTROLS[key], enabled)
    if "agent_governance" in req.controls:
        for key in AGENT_GOVERNANCE_CONTROL_KEYS:
            object.__setattr__(settings, SECURITY_CONTROLS[key], req.controls["agent_governance"])
    return _config_summary(request)


@app.post("/api/gateway/reset")
def reset_gateway(request: Request) -> dict:
    if not _runtime_toggles_allowed(request):
        raise HTTPException(status_code=403, detail="Runtime lab toggles are disabled for this host.")
    reset_gateway_budget()
    return {"status": "reset", **_config_summary(request)}


@app.post("/api/lab/reset-data")
def reset_lab_data(request: Request) -> dict:
    if not _runtime_toggles_allowed(request):
        raise HTTPException(status_code=403, detail="Runtime lab probes are disabled for this host.")
    settings = get_settings()
    if not (settings.offline_mode or settings.local_data_mode):
        raise HTTPException(status_code=400, detail="Lab data reset is only available for local SQLite data.")
    from src.agents.tools.db import reset_offline_db  # noqa: PLC0415

    reset_offline_db()
    reset_gateway_budget()
    return {"status": "reset", "data_backend": "local-sqlite"}


@app.post("/api/lab/doc-security-probe", response_model=ChatResponse)
def doc_security_probe(req: ChatRequest, request: Request) -> ChatResponse:
    if not _runtime_toggles_allowed(request):
        raise HTTPException(status_code=403, detail="Runtime lab probes are disabled for this host.")
    from src.agents.tools.search import SearchConfigurationError, search_documents  # noqa: PLC0415

    identity = _identity_from_request(request, req)
    groups = identity.zava_groups or identity.groups or req.groups
    try:
        docs = search_documents("private client terms", caller_groups=groups, top=3)
    except SearchConfigurationError as exc:
        return ChatResponse(
            answer=(
                "Document security failed closed. Azure AI Search document-level security "
                "is enabled, but the secure Search endpoint is not configured for this host. "
                "No untrimmed private-client documents were returned."
            ),
            agent="knowledge",
            events=[f"doc-security: failed closed before returning untrimmed documents ({exc})"],
            blocked=True, requires_approval=None, sources=[],
        )
    if not docs:
        return ChatResponse(
            answer="No documents returned for this caller.", agent="knowledge",
            events=["doc-security: no accessible documents returned"],
            blocked=False, requires_approval=None, sources=[],
        )
    lines = [f"- {doc['title']}: {doc['content'][:220].strip()}" for doc in docs]
    return ChatResponse(
        answer="Document probe returned:\n" + "\n".join(lines), agent="knowledge",
        events=[f"doc-security: returned {len(docs)} document(s) for groups {groups or ['none']}"],
        blocked=False, requires_approval=None,
        sources=[{"id": doc.get("id"), "title": doc.get("title")} for doc in docs],
    )


@app.post("/api/lab/rag-injection-probe", response_model=ChatResponse)
def rag_injection_probe(req: ChatRequest, request: Request) -> ChatResponse:
    if not _runtime_toggles_allowed(request):
        raise HTTPException(status_code=403, detail="Runtime lab probes are disabled for this host.")
    from src.agents.guard.guard import SafetyViolation, shield_prompt  # noqa: PLC0415
    from src.agents.tools.search import SearchConfigurationError, search_documents  # noqa: PLC0415

    identity = _identity_from_request(request, req)
    groups = identity.zava_groups or identity.groups or req.groups
    try:
        docs = search_documents("current savings rates", caller_groups=groups, top=3)
    except SearchConfigurationError as exc:
        return ChatResponse(
            answer=f"RAG retrieval failed closed: {exc}", agent="knowledge",
            events=["rag-injection: failed closed before returning untrusted documents"],
            blocked=True, requires_approval=None, sources=[],
        )
    safe_docs: list[dict[str, Any]] = []
    events = [f"rag-injection: retrieved {len(docs)} document(s)"]
    blocked_docs: list[str] = []
    for doc in docs:
        try:
            shield_prompt(doc["content"], source="document")
            safe_docs.append(doc)
        except SafetyViolation as exc:
            blocked_docs.append(doc["id"])
            events.append(f"prompt-shield BLOCKED document '{doc['id']}' ({exc.category})")
        except Exception:  # noqa: BLE001 - secure guardrail failures fail closed for the lab
            return ChatResponse(
                answer="RAG Prompt Shields failed closed because Azure guardrail configuration is unavailable.",
                agent="knowledge",
                events=["rag-injection: Prompt Shields unavailable; failed closed"],
                blocked=True, requires_approval=None, sources=[],
            )
    visible_docs = safe_docs if blocked_docs else docs
    lines = [f"- {doc['title']}: {doc['content'][:220].strip()}" for doc in visible_docs]
    if blocked_docs:
        answer = f"Blocked poisoned document(s): {', '.join(blocked_docs)}. Safe documents returned:\n" + "\n".join(lines)
    else:
        answer = "RAG probe returned untrusted document content:\n" + "\n".join(lines)
    return ChatResponse(
        answer=answer, agent="knowledge", events=events,
        blocked=bool(blocked_docs), requires_approval=None,
        sources=[{"id": doc.get("id"), "title": doc.get("title")} for doc in visible_docs],
    )


@app.post("/api/lab/mcp-transfer-probe", response_model=ChatResponse)
def mcp_transfer_probe(request: Request) -> ChatResponse:
    if not _runtime_toggles_allowed(request):
        raise HTTPException(status_code=403, detail="Runtime lab probes are disabled for this host.")
    from src.agents.tools.mcp import call_mcp_tool  # noqa: PLC0415

    identity = _identity_from_request(request)
    ctx = AgentContext(
        customer_id=identity.customer_id or get_settings().default_customer_id,
        groups=identity.zava_groups or identity.groups or ["retail-customers"],
    )
    try:
        result = call_mcp_tool(
            "transfer_funds",
            ctx,
            from_account="ACC-100001",
            to_account="ACC-200001",
            amount=1,
            caller_id=ctx.customer_id,
            caller_groups=ctx.groups,
            approved=True,
        )
    except Exception as exc:  # noqa: BLE001 - lab probe reports the boundary decision
        return ChatResponse(
            answer=str(exc), agent="mcp",
            events=["mcp: state-changing transfer_funds probe blocked"],
            blocked=True, requires_approval=None, sources=[],
        )
    return ChatResponse(
        answer=f"MCP transfer probe executed: {result['data']}", agent="mcp",
        events=[f"mcp: transfer_funds executed via {result['server']}"],
        blocked=False, requires_approval=None, sources=[],
    )


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
        description = request.query_params.get("error_description", "")
        logging.warning("Entra login returned error: %s %s", error, description)
        detail = f": {description}" if description else ""
        return HTMLResponse(f"Entra login failed: {error}{detail}", status_code=400)
    flow = _decode_cookie_json(request.cookies.get(_AUTH_FLOW_COOKIE)) or {}
    if not flow:
        logging.warning("Entra login failed: auth flow cookie is missing or invalid.")
        return HTMLResponse(
            "Entra login failed: local auth state was lost. Start sign-in again.",
            status_code=400,
        )
    if flow.get("state") != request.query_params.get("state"):
        logging.warning("Entra login failed: state mismatch.")
        return HTMLResponse("Entra login failed: invalid state.", status_code=400)

    import httpx  # noqa: PLC0415

    try:
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
    except httpx.HTTPError as exc:
        logging.exception("Entra token exchange failed before receiving a response.")
        return HTMLResponse(f"Entra token exchange failed: {exc}", status_code=502)
    if token_response.status_code >= 400:
        logging.warning(
            "Entra token exchange returned %s: %s",
            token_response.status_code,
            token_response.text,
        )
        return HTMLResponse(f"Entra token exchange failed: {token_response.text}", status_code=400)
    try:
        token_body = token_response.json()
    except ValueError as exc:
        logging.exception("Entra token exchange returned non-JSON content.")
        return HTMLResponse(f"Entra token exchange failed: invalid token response ({exc})", status_code=502)
    if not token_body.get("id_token"):
        logging.warning("Entra token exchange response did not include an id_token.")
        return HTMLResponse("Entra token exchange failed: missing id_token.", status_code=502)
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
    gateway_events: list[str] = []
    if settings.enable_ai_gateway:
        try:
            estimated_tokens = req.lab_estimated_tokens or max(25, len(req.message) // 4 + 50)
            decision = route_call(
                estimated_tokens=estimated_tokens,
                authenticated=identity.authenticated or not settings.enable_obo,
            )
            gateway_events.append(
                f"gateway: APIM allowed estimated {estimated_tokens} token(s); {decision.tokens_remaining} remaining"
            )
        except GatewayError as exc:
            return ChatResponse(
                answer=str(exc), agent="orchestrator",
                events=["gateway: APIM rejected the request"],
                blocked=True, requires_approval=None, sources=[],
            )
    try:
        if req.message == "__lab_v7_error__":
            raise RuntimeError("debug leak: db password=hunter2 at C:/zava/app/db.py:42")
        result = handle_turn(req.message, ctx)
    except ModelSafetyBlocked as exc:
        logging.info("chat turn blocked by model safety policy: %s", exc)
        return ChatResponse(
            answer=str(exc), agent="orchestrator",
            events=["model: Azure Foundry content filter blocked the request"],
            blocked=True, requires_approval=None, sources=[],
        )
    except Exception as exc:  # noqa: BLE001 - surface a safe/unsafe error per V7
        logging.exception("chat turn failed")
        return ChatResponse(
            answer=format_error(exc), agent="orchestrator", events=[],
            blocked=True, requires_approval=None, sources=[],
        )
    return ChatResponse(
        answer=result.answer,
        agent=result.agent,
        events=[*gateway_events, *result.events],
        blocked=result.blocked,
        requires_approval=result.requires_approval,
        sources=result.sources,
    )


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
