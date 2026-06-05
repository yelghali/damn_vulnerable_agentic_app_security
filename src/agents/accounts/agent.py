"""Accounts agent — read-only customer data tools (V4)."""

from __future__ import annotations

import re

from src.agents.tools.db import (
    ToolError,
    get_accounts,
    get_credit_score,
    get_customer_profile,
    get_transactions,
)
from src.agents.guard.guard import SafetyViolation, scan_tool_output
from src.agents.tools.mcp import call_mcp_tool
from src.agents.types import AgentContext, TurnResult
from src.config import get_settings


def _call_data_tool(name: str, ctx: AgentContext, **kwargs) -> tuple[object, str]:
    settings = get_settings()
    if settings.use_mcp_tools and name in {"get_accounts", "get_transactions", "get_credit_score"}:
        result = call_mcp_tool(name, ctx, **kwargs)
        scan_tool_output(result, source="mcp")
        return result["data"], f"accounts: MCP {name}({kwargs}) via {result['server']}"
    local = {
        "get_accounts": get_accounts,
        "get_transactions": get_transactions,
        "get_credit_score": get_credit_score,
    }[name]
    return local(**kwargs), f"accounts: {name}({next(iter(kwargs.values()), '')})"


def _target_customer(message: str, ctx: AgentContext) -> str | None:
    """Pick the customer to act on.

    LAB-VULN(V4): the vulnerable baseline lets the user name *any* customer_id
    in their message. The tool layer (least-priv) is what actually enforces that
    the caller only sees their own data in secure mode. The capture also keeps
    any SQL-injection suffix the user appends (e.g. ``CUST-1001' OR '1'='1``) so
    the string-interpolated query in ``db.get_accounts`` is reachable from chat.
    """
    m = re.search(
        r"\b(CUST-\d+(?:'\s*(?:OR|AND|UNION|--|;)[^\n]*)?)", message, re.IGNORECASE
    )
    if m:
        return m.group(1).upper()
    return ctx.customer_id


def run(message: str, ctx: AgentContext) -> TurnResult:
    events: list[str] = []
    customer_id = _target_customer(message, ctx)
    if not customer_id:
        return TurnResult(answer="Which account would you like to review?", agent="accounts")

    low = message.lower()
    try:
        if any(k in low for k in ("ssn", "social security", "profile", "personal", "address", "full name")):
            data = get_customer_profile(customer_id, caller_id=ctx.customer_id, caller_groups=ctx.groups)
            events.append(f"accounts: get_customer_profile({customer_id})")
            body = (
                f"Name: {data.get('full_name', 'n/a')}\n"
                f"SSN: {data.get('ssn', 'n/a')}\n"
                f"Email: {data.get('email', 'n/a')}\n"
                f"Address: {data.get('address', 'n/a')}"
            ) if data else "No profile found."
        elif "credit" in low or "score" in low:
            data, event = _call_data_tool("get_credit_score", ctx, customer_id=customer_id, caller_id=ctx.customer_id, caller_groups=ctx.groups)
            events.append(event)
            body = f"Credit score: {data.get('score', 'n/a')} ({data.get('bureau', '')})"
        elif "transaction" in low or "history" in low:
            acct = re.search(r"\b(ACC-\d+)\b", message, re.IGNORECASE)
            acct_id = acct.group(1).upper() if acct else None
            if not acct_id:
                accts, event = _call_data_tool("get_accounts", ctx, customer_id=customer_id, caller_id=ctx.customer_id, caller_groups=ctx.groups)
                acct_id = accts[0]["account_id"] if accts else None
            if acct_id:
                txns, event = _call_data_tool("get_transactions", ctx, account_id=acct_id, caller_id=ctx.customer_id, caller_groups=ctx.groups)
            else:
                txns, event = [], "accounts: get_transactions(None)"
            events.append(event)
            body = "\n".join(
                f"- {t['posted_at']} {t['amount']} {t['description']}" for t in txns
            ) or "No transactions found."
        else:
            accts, event = _call_data_tool("get_accounts", ctx, customer_id=customer_id, caller_id=ctx.customer_id, caller_groups=ctx.groups)
            events.append(event)
            body = "\n".join(
                f"- {a['account_id']} {a['account_type']}: {a['balance']} {a['currency']}"
                for a in accts
            ) or "No accounts found."
    except (ToolError, SafetyViolation) as e:
        return TurnResult(answer=str(e), agent="accounts", events=events, blocked=True)

    return TurnResult(answer=body, agent="accounts", events=events)
