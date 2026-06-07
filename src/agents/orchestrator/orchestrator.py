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
from src.agents.guard.guard import (
    SafetyViolation,
    check_content_safety,
    guard_agent_message,
    redact_pii,
    shield_prompt,
)
from src.agents.knowledge import agent as knowledge_agent
from src.agents.model import compose_answer
from src.agents.prompts import load_system_prompt
from src.agents.reporting import agent as reporting_agent
from src.agents.telemetry import agent_span, record_agent_result
from src.agents.transactions import agent as transactions_agent
from src.agents.types import AgentContext, TurnResult

logger = logging.getLogger("zava.orchestrator")


def _route(message: str) -> str:
    low = message.lower()
    if any(k in low for k in ("system prompt", "your instructions", "admin override")):
        return "orchestrator"
    if any(
        k in low
        for k in (
            "inferior race",
            "offensive joke",
            "build a bomb",
            "explicit sexual",
            "kill myself",
            "end my life",
            "political party",
            "vote for",
            "election",
        )
    ):
        return "orchestrator"
    if any(k in low for k in ("transfer", "send", "email", "statement", "pay")):
        return "transactions"
    if any(k in low for k in ("report", "summary", "chart", "summarize")):
        return "reporting"
    if any(k in low for k in ("document", "policy", "disclosure", "fee", "interest", "terms", "rate")):
        return "knowledge"
    if any(k in low for k in ("account", "balance", "transaction", "credit", "score")):
        return "accounts"
    return "orchestrator"


def _deliver_handoff(result: TurnResult, ctx: AgentContext) -> TurnResult:
    """Deliver a specialist's cross-agent handoff after re-scanning it (V11).

    Secure: ``guard_agent_message`` blocks a forged state-changing directive.
    Vulnerable: the message is trusted and the receiving agent executes it.
    """
    ho = result.handoff or {}
    to_agent = ho.get("to", "")
    payload = ho.get("message", "")
    try:
        guard_agent_message(payload, from_agent=result.agent, to_agent=to_agent)
    except SafetyViolation as v:
        result.events.append(f"A2A BLOCKED ({v.category}): refused {result.agent} -> {to_agent} handoff")
        result.handoff = None
        return result

    # Guard passed (or is off): dispatch to the named agent.
    if to_agent == "transactions":
        with agent_span("transactions", payload, ctx) as span:
            sub = transactions_agent.run(payload, ctx)
            record_agent_result(span, "transactions", sub)
        result.events.append(f"A2A: {result.agent} -> transactions handoff executed")
        result.events += [f"  {e}" for e in sub.events]
        result.answer += f"\n\n[handoff → transactions]: {sub.answer}"
        if sub.requires_approval:
            result.requires_approval = sub.requires_approval
    else:
        result.events.append(f"A2A: handoff to unknown agent '{to_agent}' ignored")
    result.handoff = None
    return result


def handle_turn(message: str, ctx: AgentContext) -> TurnResult:
    with agent_span("orchestrator", message, ctx) as orchestrator_span:
        result = _handle_turn(message, ctx)
        record_agent_result(orchestrator_span, "orchestrator", result)
        return result


def _handle_turn(message: str, ctx: AgentContext) -> TurnResult:
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
    if route == "orchestrator":
        with agent_span("orchestrator.model", message, ctx) as span:
            result = TurnResult(
                answer=compose_answer(load_system_prompt(), message),
                agent="orchestrator",
            )
            record_agent_result(span, "orchestrator.model", result)
    elif route == "accounts":
        with agent_span("accounts", message, ctx) as span:
            result = accounts_agent.run(message, ctx)
            record_agent_result(span, "accounts", result)
    elif route == "transactions":
        with agent_span("transactions", message, ctx) as span:
            result = transactions_agent.run(message, ctx)
            record_agent_result(span, "transactions", result)
    elif route == "reporting":
        with agent_span("reporting", message, ctx) as span:
            result = reporting_agent.run(message, ctx)
            record_agent_result(span, "reporting", result)
    else:
        with agent_span("knowledge", message, ctx) as span:
            result = knowledge_agent.run(message, ctx)
            record_agent_result(span, "knowledge", result)

    result.events = events + result.events

    # 3b. AGENT-TO-AGENT handoff (V11) --------------------------------------
    # A specialist may ask the orchestrator to deliver a control message to
    # another agent. We re-scan that message at the boundary before acting on
    # it; when the guard is off the forged directive executes (poisoning).
    if result.handoff and not result.blocked:
        result = _deliver_handoff(result, ctx)

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
