"""Transactions agent — state-changing tools with human-in-the-loop (V4)."""

from __future__ import annotations

import re

from src.agents.tools.db import ToolError, get_accounts, transfer_funds
from src.agents.tools.email import EmailError, send_statement_email
from src.agents.types import AgentContext, TurnResult
from src.config import get_settings


def _resolve_account(text: str, ctx: AgentContext) -> str | None:
    """Turn a free-text account reference into an account id.

    Accepts the canonical ``ACC-123456`` form, a named account ("my checking",
    "savings"), or a bare destination number ("account 999"). Named accounts are
    resolved against the caller's own accounts. A bare/unknown number is kept as
    ``ACC-<n>`` on purpose — the vulnerable baseline never validates that the
    destination exists, which is exactly what the V4 exploit demonstrates.
    """
    low = text.strip().lower()
    m = re.search(r"acc-\d+", low)
    if m:
        return m.group(0).upper()
    for kind in ("checking", "savings"):
        if kind in low:
            for a in get_accounts(ctx.customer_id or "", caller_id=ctx.customer_id):
                if a["account_type"] == kind:
                    return a["account_id"]
            return None
    m = re.search(r"\d{2,}", low)
    if m:
        return f"ACC-{m.group(0)}"
    return None


def _parse_transfer(message: str, ctx: AgentContext) -> dict | None:
    """Parse a transfer request, tolerating natural phrasing.

    Matches the strict ``from ACC-… to ACC-…`` form *and* friendlier wordings
    like ``Transfer $5000 from my checking to account 999`` so the documented
    exploit works exactly as written in the workshop.
    """
    m = re.search(
        r"transfer\s+\$?([\d,]+(?:\.\d+)?)\s*(?:usd|dollars?|eur|gbp)?\s+"
        r"from\s+(.+?)\s+to\s+(.+?)(?:[.?!]|$)",
        message,
        re.IGNORECASE,
    )
    if not m:
        return None
    from_account = _resolve_account(m.group(2), ctx)
    to_account = _resolve_account(m.group(3), ctx)
    if not from_account or not to_account:
        return None
    return {
        "tool": "transfer_funds",
        "amount": float(m.group(1).replace(",", "")),
        "from_account": from_account,
        "to_account": to_account,
    }


def run(message: str, ctx: AgentContext) -> TurnResult:
    settings = get_settings()
    events: list[str] = []
    action = _parse_transfer(message, ctx)

    if action:
        # HITL: in secure mode, return an approval request instead of acting.
        if settings.enable_hitl and not (ctx.approved_action and ctx.approved_action.get("tool") == "transfer_funds"):
            events.append("transactions: HITL approval required for transfer_funds")
            return TurnResult(
                answer=(
                    f"Please confirm: transfer {action['amount']} from "
                    f"{action['from_account']} to {action['to_account']}?"
                ),
                agent="transactions",
                events=events,
                requires_approval=action,
            )
        try:
            result = transfer_funds(
                action["from_account"],
                action["to_account"],
                action["amount"],
                caller_id=ctx.customer_id,
                approved=bool(ctx.approved_action),
            )
            events.append(f"transactions: transfer_funds executed -> {result['status']}")
            return TurnResult(
                answer=f"Transfer {result['status']}: {result['amount']} "
                f"from {result['from']} to {result['to']}.",
                agent="transactions",
                events=events,
            )
        except ToolError as e:
            return TurnResult(answer=str(e), agent="transactions", events=events, blocked=True)

    if "statement" in message.lower() or "email" in message.lower():
        to = re.search(r"to\s+([\w.+-]+@[\w-]+\.[\w.-]+)", message)
        if settings.enable_hitl and not (ctx.approved_action and ctx.approved_action.get("tool") == "send_statement_email"):
            action = {"tool": "send_statement_email", "to_address": to.group(1) if to else None}
            events.append("transactions: HITL approval required for send_statement_email")
            return TurnResult(
                answer="Confirm sending your statement by email?",
                agent="transactions",
                events=events,
                requires_approval=action,
            )
        try:
            result = send_statement_email(
                ctx.customer_id or "",
                to_address=to.group(1) if to else None,
                caller_id=ctx.customer_id,
                approved=bool(ctx.approved_action),
            )
            events.append(f"transactions: send_statement_email -> {result['to']}")
            return TurnResult(answer=f"Statement sent to {result['to']}.", agent="transactions", events=events)
        except EmailError as e:
            return TurnResult(answer=str(e), agent="transactions", events=events, blocked=True)

    return TurnResult(
        answer="I can transfer funds or email your statement. What would you like to do?",
        agent="transactions",
    )
