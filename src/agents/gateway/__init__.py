"""AI gateway (Azure API Management) shim for the lab — see ``gateway.py``."""

from src.agents.gateway.gateway import (
    GatewayDecision,
    GatewayError,
    model_client_base_url,
    reset_gateway_budget,
    route_call,
)

__all__ = [
    "GatewayDecision",
    "GatewayError",
    "model_client_base_url",
    "reset_gateway_budget",
    "route_call",
]
