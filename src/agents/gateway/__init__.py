"""AI gateway (Azure API Management) shim for the lab — see ``gateway.py``."""

from src.agents.gateway.gateway import (
    GatewayDecision,
    GatewayError,
    reset_gateway_budget,
    route_call,
)

__all__ = ["GatewayDecision", "GatewayError", "reset_gateway_budget", "route_call"]
