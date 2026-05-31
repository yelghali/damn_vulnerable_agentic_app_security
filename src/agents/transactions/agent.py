"""Transactions agent — state-changing tools with human-in-the-loop (V4)."""

from __future__ import annotations

import re

from src.agents.tools.db import ToolError, transfer_funds
from src.agents.tools.email import EmailError, send_statement_email
from src.agents.types import AgentContext, TurnResult
from src.config import get_settings


def _parse_transfer(message: str) -> dict | None:
    m = re.search(
        r"transfer\s+\$?([\d.]+)\s*(?:usd|dollars?|eur|gbp)?\s+from\s+(ACC-\d+)\s+to\s+(ACC-\d+)",
        message,
        re.IGNORECASE,
    )
    if not m:
        return None
    return {
        "tool": "transfer_funds",
        "amount": float(m.group(1)),
        "from_account": m.group(2).upper(),
        "to_account": m.group(3).upper(),
    }


def run(message: str, ctx: AgentContext) -> TurnResult:
    settings = get_settings()
    events: list[str] = []
    action = _parse_transfer(message)

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
