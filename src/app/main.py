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

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.agents.orchestrator.orchestrator import handle_turn
from src.agents.types import AgentContext
from src.config import get_settings

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Zava Wealth Advisor (Damn Vulnerable Agentic App)")
_STATIC = Path(__file__).resolve().parent / "static"


class ChatRequest(BaseModel):
    message: str
    customer_id: str | None = "CUST-1001"
    groups: list[str] = ["retail-customers"]
    approved_action: dict | None = None


class ChatResponse(BaseModel):
    answer: str
    agent: str
    events: list[str]
    blocked: bool
    requires_approval: dict | None
    sources: list[dict]


@app.get("/api/config")
def config() -> dict:
    return get_settings().summary()


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
def chat(req: ChatRequest) -> ChatResponse:
    ctx = AgentContext(
        customer_id=req.customer_id,
        groups=req.groups,
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
