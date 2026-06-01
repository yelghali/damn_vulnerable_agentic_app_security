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
from src.agents.types import AgentContext, TurnResult


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
            data = get_customer_profile(customer_id, caller_id=ctx.customer_id)
            events.append(f"accounts: get_customer_profile({customer_id})")
            body = (
                f"Name: {data.get('full_name', 'n/a')}\n"
                f"SSN: {data.get('ssn', 'n/a')}\n"
                f"Email: {data.get('email', 'n/a')}\n"
                f"Address: {data.get('address', 'n/a')}"
            ) if data else "No profile found."
        elif "credit" in low or "score" in low:
            data = get_credit_score(customer_id, caller_id=ctx.customer_id)
            events.append(f"accounts: get_credit_score({customer_id})")
            body = f"Credit score: {data.get('score', 'n/a')} ({data.get('bureau', '')})"
        elif "transaction" in low or "history" in low:
            acct = re.search(r"\b(ACC-\d+)\b", message, re.IGNORECASE)
            acct_id = acct.group(1).upper() if acct else None
            if not acct_id:
                accts = get_accounts(customer_id, caller_id=ctx.customer_id)
                acct_id = accts[0]["account_id"] if accts else None
            txns = get_transactions(acct_id, caller_id=ctx.customer_id) if acct_id else []
            events.append(f"accounts: get_transactions({acct_id})")
            body = "\n".join(
                f"- {t['posted_at']} {t['amount']} {t['description']}" for t in txns
            ) or "No transactions found."
        else:
            accts = get_accounts(customer_id, caller_id=ctx.customer_id)
            events.append(f"accounts: get_accounts({customer_id})")
            body = "\n".join(
                f"- {a['account_id']} {a['account_type']}: {a['balance']} {a['currency']}"
                for a in accts
            ) or "No accounts found."
    except ToolError as e:
        return TurnResult(answer=str(e), agent="accounts", events=events, blocked=True)

    return TurnResult(answer=body, agent="accounts", events=events)
