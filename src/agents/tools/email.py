"""Outbound email tool (state-changing) for the Transactions agent.

LAB-VULN(V4): the vulnerable baseline "sends" to any address the model supplies
with no confirmation and no check that the recipient belongs to the customer
(data exfiltration via a crafted prompt). Secure mode requires HITL approval and
restricts the recipient to the customer's address on file.

Offline mode records "sent" messages in memory instead of contacting a mail
service, so the behaviour is observable and testable.
"""

from __future__ import annotations

from typing import Any

from src.agents.tools.db import _offline_conn  # reuse seeded store
from src.config import get_settings

# In-memory outbox for offline/testing.
SENT_OUTBOX: list[dict[str, Any]] = []


class EmailError(RuntimeError):
    pass


def send_statement_email(
    customer_id: str,
    to_address: str | None = None,
    caller_id: str | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    settings = get_settings()

    conn = _offline_conn()
    try:
        row = conn.execute(
            "SELECT email FROM customers WHERE customer_id = ?", (customer_id,)
        ).fetchone()
    finally:
        conn.close()
    on_file = row["email"] if row else None

    if settings.enable_tool_least_priv:
        if caller_id != customer_id:
            raise EmailError("Access denied: cannot email statements for another customer.")
        # SECURE: ignore any model-supplied address; always use the address on file.
        recipient = on_file
        if settings.enable_hitl and not approved:
            raise EmailError("send_statement_email requires human approval (HITL).")
    else:
        # LAB-VULN(V4): trust the model-supplied recipient -> exfiltration.
        recipient = to_address or on_file

    if not recipient:
        raise EmailError("No recipient address available.")

    message = {
        "customer_id": customer_id,
        "to": recipient,
        "subject": "Your Zava account statement",
        "body": f"Statement for customer {customer_id} attached.",
    }
    SENT_OUTBOX.append(message)
    return {"status": "sent", **message}
