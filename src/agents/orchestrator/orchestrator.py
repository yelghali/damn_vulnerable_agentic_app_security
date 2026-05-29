"""Orchestrator / planner — the entry agent.

Pipeline per turn (Microsoft Agent Framework middleware in Azure mode; the same
logic runs inline offline):

  1. INPUT guards  — Content Safety (V1/V2), Prompt Shields (V2), PII redaction
     for logging (V3).
  2. ROUTE          — pick the specialist agent for the user's intent.
  3. RUN agent      — knowledge / accounts / transactions / reporting.
  4. OUTPUT guards  — PII redaction (V3) + Content Safety on the response.

When the relevant toggle is off, the matching guard is a no-op, so the
vulnerable baseline passes harmful input straight through and leaks PII.
"""

from __future__ import annotations

import logging

from src.agents.accounts import agent as accounts_agent
from src.agents.guard.guard import SafetyViolation, check_content_safety, redact_pii, shield_prompt
from src.agents.knowledge import agent as knowledge_agent
from src.agents.model import compose_answer
from src.agents.prompts import load_system_prompt
from src.agents.reporting import agent as reporting_agent
from src.agents.transactions import agent as transactions_agent
from src.agents.types import AgentContext, TurnResult

logger = logging.getLogger("zava.orchestrator")


def _route(message: str) -> str:
    low = message.lower()
    if any(k in low for k in ("transfer", "send", "email", "statement", "pay")):
        return "transactions"
    if any(k in low for k in ("report", "summary", "chart", "summarize")):
        return "reporting"
    if any(k in low for k in ("account", "balance", "transaction", "credit", "score")):
        return "accounts"
    if any(k in low for k in ("document", "policy", "disclosure", "fee", "interest", "terms")):
        return "knowledge"
    return "knowledge"


def handle_turn(message: str, ctx: AgentContext) -> TurnResult:
    events: list[str] = []

    # 1. INPUT guards -------------------------------------------------------
    try:
        check_content_safety(message)
        shield_prompt(message, source="user")
    except SafetyViolation as v:
        events.append(f"INPUT BLOCKED ({v.category}): {v}")
        return TurnResult(answer=f"Request blocked: {v}", events=events, blocked=True)

    # V3: redact PII before anything is logged.
    pii = redact_pii(message)
    if pii.entities:
        events.append(f"pii: redacted {len(pii.entities)} entity(ies) before logging")
    logger.info("user turn: %s", pii.text)

    # 2. ROUTE + 3. RUN -----------------------------------------------------
    route = _route(message)
    events.append(f"orchestrator: routed to '{route}' agent")
    if route == "accounts":
        result = accounts_agent.run(message, ctx)
    elif route == "transactions":
        result = transactions_agent.run(message, ctx)
    elif route == "reporting":
        result = reporting_agent.run(message, ctx)
    else:
        result = knowledge_agent.run(message, ctx)

    # If the agent only returned tool data, let the model phrase it.
    if result.agent in {"accounts", "reporting"} and not result.blocked:
        result.answer = compose_answer(load_system_prompt(), message, result.answer)

    result.events = events + result.events

    # 4. OUTPUT guards ------------------------------------------------------
    if not result.blocked:
        out_pii = redact_pii(result.answer)
        if out_pii.entities:
            result.events.append(f"pii: redacted {len(out_pii.entities)} entity(ies) from response")
        result.answer = out_pii.text
        try:
            check_content_safety(result.answer)
        except SafetyViolation as v:
            result.events.append(f"OUTPUT BLOCKED ({v.category})")
            return TurnResult(answer="Response withheld by content safety.", events=result.events, blocked=True)

    return result
