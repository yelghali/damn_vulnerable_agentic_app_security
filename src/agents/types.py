"""Shared types for the multi-agent system."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentContext:
    """The authenticated caller's context, propagated to every agent + tool.

    In the secure path ``customer_id`` and ``groups`` come from the validated
    Entra (OBO) token; in the vulnerable baseline the client can spoof them.
    """

    customer_id: str | None = None
    groups: list[str] = field(default_factory=list)
    # Pending human-in-the-loop approval for a state-changing action.
    approved_action: dict[str, Any] | None = None


@dataclass
class TurnResult:
    """Result of one orchestrator turn, with a trace the UI can render."""

    answer: str
    agent: str = "orchestrator"
    events: list[str] = field(default_factory=list)
    blocked: bool = False
    requires_approval: dict[str, Any] | None = None
    sources: list[dict[str, Any]] = field(default_factory=list)
