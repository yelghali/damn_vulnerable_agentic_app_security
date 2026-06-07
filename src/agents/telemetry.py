"""Application Insights telemetry helpers for agent traces (V7/V10).

The lab uses one shared workspace-based Application Insights instance. Local
runs without ``APPLICATIONINSIGHTS_CONNECTION_STRING`` keep working; Azure
Container Apps receive the connection string from Terraform and export logs,
requests, dependencies, and custom spans.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import logging
from typing import Any, Iterator

from src.config import get_settings

logger = logging.getLogger("zava.telemetry")

try:  # Optional so Part 1 local setup does not require Azure telemetry packages.
    from azure.monitor.opentelemetry import configure_azure_monitor
    from opentelemetry import trace
    from opentelemetry.trace import Span
except Exception:  # noqa: BLE001 - telemetry must never block the lab app
    configure_azure_monitor = None
    trace = None
    Span = Any  # type: ignore[misc,assignment]

_CONFIGURED = False


def configure_telemetry() -> bool:
    """Wire OpenTelemetry to Azure Monitor when App Insights is configured."""
    global _CONFIGURED
    if _CONFIGURED:
        return True

    settings = get_settings()
    if not settings.appinsights_connection_string:
        logger.info("telemetry: APPLICATIONINSIGHTS_CONNECTION_STRING not set; Azure export disabled")
        return False
    if configure_azure_monitor is None:
        logger.warning("telemetry: azure-monitor-opentelemetry is not installed; Azure export disabled")
        return False

    configure_azure_monitor(
        connection_string=settings.appinsights_connection_string,
        logger_name="zava",
    )
    _CONFIGURED = True
    logger.info("telemetry: Azure Monitor exporter configured")
    return True


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _set_attr(span: Span, key: str, value: Any) -> None:
    if value is None:
        return
    try:
        span.set_attribute(key, value)
    except Exception:  # noqa: BLE001 - attributes are best-effort telemetry
        logger.debug("telemetry: failed to set span attribute %s", key, exc_info=True)


@contextmanager
def agent_span(agent: str, message: str, ctx: Any | None = None) -> Iterator[Span | None]:
    """Create a custom span around one agent boundary.

    The raw prompt is intentionally not stored. App Insights receives a stable
    hash and length so instructors can correlate turns without leaking PII.
    """
    if trace is None:
        yield None
        return

    tracer = trace.get_tracer("zava.agents")
    with tracer.start_as_current_span(f"agent.{agent}") as span:
        _set_attr(span, "zava.agent", agent)
        _set_attr(span, "zava.message_hash", _hash_text(message))
        _set_attr(span, "zava.message_length", len(message))
        if ctx is not None:
            _set_attr(span, "zava.customer_id", getattr(ctx, "customer_id", None))
            groups = getattr(ctx, "groups", []) or []
            _set_attr(span, "zava.groups", ",".join(groups))
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            _set_attr(span, "zava.blocked", True)
            raise


def record_agent_result(span: Span | None, agent: str, result: Any) -> None:
    """Attach high-signal agent result metadata to traces and logs."""
    blocked = bool(getattr(result, "blocked", False))
    events = list(getattr(result, "events", []) or [])
    sources = list(getattr(result, "sources", []) or [])
    requires_approval = getattr(result, "requires_approval", None) is not None

    if span is not None:
        _set_attr(span, "zava.result_agent", getattr(result, "agent", agent))
        _set_attr(span, "zava.blocked", blocked)
        _set_attr(span, "zava.event_count", len(events))
        _set_attr(span, "zava.source_count", len(sources))
        _set_attr(span, "zava.requires_approval", requires_approval)
        for event in events[:20]:
            span.add_event("zava.agent.event", {"message": event[:512]})

    logging.getLogger(f"zava.agent.{agent}").info(
        "agent turn completed",
        extra={
            "zava_agent": agent,
            "result_agent": getattr(result, "agent", agent),
            "blocked": blocked,
            "event_count": len(events),
            "source_count": len(sources),
            "requires_approval": requires_approval,
        },
    )