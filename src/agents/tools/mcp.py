"""MCP tool transport boundary (LAB-VULN V9).

A tool's *implementation* (see ``db.py``) is independent of how the agent
*reaches* it. The Zava data tools can be called two ways:

* **local function calls** (in-process), or
* a remote **MCP server** — e.g. the **Azure Database for PostgreSQL MCP
  server** attached to a Foundry agent as a hosted MCP tool.

This module is that seam. In ``OFFLINE_MODE`` the "MCP server" is simulated by
dispatching to the same local ``db`` functions, but the *transport security*
differs by mode so the before/after is teachable without Azure:

* **Vulnerable** (``enable_mcp_tool_security=False``):
    - connects to whatever ``PG_MCP_SERVER_URL`` is configured — an unpinned /
      untrusted server (supply-chain risk, LLM03)
    - exposes **every** advertised tool (no allow-list -> tool misuse, T2)
    - returns the server's response as **trusted** text, so a poisoned MCP
      tool result becomes an indirect prompt injection (T12 / LLM01)
* **Secure** (``enable_mcp_tool_security=True``):
    - requires a **pinned / approved** server
    - enforces an explicit per-call **tool allow-list**
    - tags output as **untrusted** so the guard middleware re-scans it before
      it reaches the model
"""

from __future__ import annotations

from typing import Any, Callable

from src.agents.tools.db import (
    ToolError,
    get_accounts,
    get_credit_score,
    get_transactions,
    transfer_funds,
)
from src.agents.types import AgentContext
from src.config import get_settings

# Servers we trust to advertise tools. In offline mode the simulated server is
# always considered approved; in Azure mode the secure path requires the
# configured PG_MCP_SERVER_URL to appear here (set via deployment).
_OFFLINE_SERVER = "mcp://offline"
_TRUSTED_SERVERS = {_OFFLINE_SERVER}


class MCPToolError(ToolError):
    """Raised when the MCP transport refuses a call (untrusted server,
    tool not on the allow-list, etc.)."""


# Tools the simulated MCP server "advertises". The vulnerable path will call
# any of these; the secure path intersects this with the allow-list.
_DISPATCH: dict[str, Callable[..., Any]] = {
    "get_accounts": get_accounts,
    "get_transactions": get_transactions,
    "get_credit_score": get_credit_score,
    "transfer_funds": transfer_funds,
}


def advertised_tools() -> list[str]:
    """Tools the (simulated) MCP server exposes."""
    return sorted(_DISPATCH)


def allowed_tools() -> set[str]:
    """Per-agent allow-list parsed from config (secure mode only)."""
    raw = get_settings().mcp_tool_allowlist
    return {t.strip() for t in raw.split(",") if t.strip()}


def _is_admin(ctx: AgentContext) -> bool:
    configured = {g.strip() for g in get_settings().admin_groups.split(",") if g.strip()}
    return bool(configured.intersection(ctx.groups or []))


def _server_url() -> str:
    settings = get_settings()
    if settings.offline_mode or settings.local_data_mode:
        return _OFFLINE_SERVER
    return settings.pg_mcp_server_url


def _is_trusted(server_url: str) -> bool:
    settings = get_settings()
    configured = {s.strip().rstrip("/") for s in settings.pg_mcp_server_url.split(",") if s.strip()}
    return server_url.rstrip("/") in (_TRUSTED_SERVERS | configured)


def call_mcp_tool(name: str, ctx: AgentContext, **kwargs: Any) -> dict[str, Any]:
    """Invoke ``name`` over the MCP transport and return a structured result.

    Returns ``{"tool", "server", "data", "untrusted"}``. ``untrusted`` is True
    in secure mode so callers know MCP output must pass through the guard
    middleware before being trusted.
    """
    settings = get_settings()
    server_url = _server_url()

    if name not in _DISPATCH:
        raise MCPToolError(f"MCP server does not advertise tool '{name}'.")

    if settings.enable_mcp_tool_security:
        # 1) Only talk to a pinned / approved server.
        if not server_url or not _is_trusted(server_url):
            raise MCPToolError(
                f"Refusing to use untrusted MCP server '{server_url or '(unset)'}'."
            )
        # 2) Enforce the explicit tool allow-list.
        if name not in allowed_tools() and not _is_admin(ctx):
            raise MCPToolError(
                f"MCP tool '{name}' is not on this agent's allow-list."
            )
        # 3) Scope to the authenticated caller (defense in depth with V4).
        kwargs.setdefault("caller_id", ctx.customer_id)
        kwargs.setdefault("caller_groups", ctx.groups)
        data = _DISPATCH[name](**kwargs)
        # 4) Output is untrusted: the guard middleware must re-scan it.
        return {"tool": name, "server": server_url, "data": data, "untrusted": True}

    # LAB-VULN(V9): vulnerable transport.
    #   - no server pinning (any PG_MCP_SERVER_URL is used as-is)
    #   - no allow-list: every advertised tool is callable, including the
    #     state-changing transfer_funds
    #   - the result is returned as trusted text (no re-scan), so a poisoned
    #     MCP tool response flows straight into the model.
    data = _DISPATCH[name](**kwargs)
    return {"tool": name, "server": server_url, "data": data, "untrusted": False}
