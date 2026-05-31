"""AI gateway shim (LAB-VULN V10) — Azure API Management in front of models + tools.

In the secure end-state, every model call and every MCP/tool endpoint is
reached through **Azure API Management acting as an AI gateway**. APIM gives one
governed choke point for:

* **authentication / authorization** (validate the Entra/OBO token centrally),
* **token-based rate limiting** (GenAI token-limit policy) to bound spend +
  resist resource-exhaustion (LLM10 / T4),
* **key vaulting** — the model key lives in APIM, never in the app or the
  client,
* **logging** of every request/response for traceability (T8).

This module models those policies so the before/after is testable offline.

* **Vulnerable** (``enable_ai_gateway=False``):
    - the app calls the model/tool endpoint **directly** with a static key,
    - no central auth, no throttling, the key can leak to clients.
* **Secure** (``enable_ai_gateway=True``):
    - calls are routed through the gateway, which **requires authentication**,
      **enforces a token budget**, and **hides the model key**.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from src.config import get_settings


class GatewayError(RuntimeError):
    """Raised when the AI gateway rejects a call (unauthenticated or over quota)."""


_lock = threading.Lock()
_tokens_used = 0


def reset_gateway_budget() -> None:
    """Reset the consumed-token counter (used by tests/scripts)."""
    global _tokens_used
    with _lock:
        _tokens_used = 0


def model_client_base_url() -> str | None:
    """Return the APIM AI-gateway base URL to route real model calls through.

    When the gateway is enabled and ``AI_GATEWAY_URL`` is set, model calls are
    sent to **Azure API Management** instead of the Foundry deployment directly.
    APIM holds the model key and enforces the rate-limit / authn / observability
    policies declared in ``infra/apim.tf`` server-side. Returns ``None`` to call
    the deployment directly (LAB-VULN V10: static key exposed, no throttling).
    """
    settings = get_settings()
    if settings.enable_ai_gateway and settings.ai_gateway_url:
        return settings.ai_gateway_url.rstrip("/")
    return None


@dataclass
class GatewayDecision:
    """Outcome of routing one call through (or around) the gateway."""

    allowed: bool
    routed_via_gateway: bool
    key_exposed_to_client: bool
    tokens_remaining: int | None


def route_call(*, estimated_tokens: int, authenticated: bool) -> GatewayDecision:
    """Decide whether a model/tool call may proceed.

    LAB-VULN(V10): when the gateway is off, the call always proceeds directly,
    no auth is required, and the model key is exposed to the client. When the
    gateway is on, unauthenticated calls and calls that exceed the token budget
    are rejected, and the key stays inside APIM.
    """
    global _tokens_used
    settings = get_settings()

    if not settings.enable_ai_gateway:
        # Direct, ungoverned exposure.
        return GatewayDecision(
            allowed=True,
            routed_via_gateway=False,
            key_exposed_to_client=True,
            tokens_remaining=None,
        )

    if not authenticated:
        raise GatewayError("AI gateway rejected an unauthenticated request.")

    with _lock:
        limit = settings.ai_gateway_token_limit
        if _tokens_used + estimated_tokens > limit:
            raise GatewayError(
                f"AI gateway token limit exceeded "
                f"({_tokens_used + estimated_tokens} > {limit})."
            )
        _tokens_used += estimated_tokens
        remaining = limit - _tokens_used

    return GatewayDecision(
        allowed=True,
        routed_via_gateway=True,
        key_exposed_to_client=False,
        tokens_remaining=remaining,
    )
