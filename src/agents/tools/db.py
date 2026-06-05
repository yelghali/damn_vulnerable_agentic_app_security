"""Data-access tools backed by Azure Database for PostgreSQL Flexible Server.

These power the Accounts and Transactions agents. The module exposes the same
tool surface in two modes:

* **Vulnerable baseline** (``enable_tool_least_priv=False``)
    - uses the *admin* connection (read / write / DDL)
    - builds SQL with string interpolation  -> SQL injection (LAB-VULN V4)
    - performs no check that ``customer_id`` belongs to the caller  -> IDOR
* **Secure path** (``enable_tool_least_priv=True``)
    - uses a least-privilege, read-only role
    - parameterized queries only
    - row-level access enforced against the authenticated principal

For local validation (``OFFLINE_MODE=true``) the same logic runs against a
seeded SQLite database so the lab is testable without Azure.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from src.config import get_settings

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_OFFLINE_DB = _DATA_DIR / "zava_offline.sqlite"
_OFFLINE_SEED = _DATA_DIR / "seed_offline.sql"
_lock = threading.Lock()


class ToolError(RuntimeError):
    """Raised when a tool refuses an action (e.g. authZ failure in secure mode)."""


# ---------------------------------------------------------------------------
# Offline SQLite store (for local testing, no Azure)
# ---------------------------------------------------------------------------
def _offline_conn() -> sqlite3.Connection:
    with _lock:
        first_time = not _OFFLINE_DB.exists()
        conn = sqlite3.connect(_OFFLINE_DB, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        if first_time and _OFFLINE_SEED.exists():
            conn.executescript(_OFFLINE_SEED.read_text(encoding="utf-8"))
            conn.commit()
    return conn


def _postgres_conn():
    """Connect to Azure Database for PostgreSQL when OFFLINE_MODE=false.

    LAB-VULN(V4): the vulnerable baseline deliberately uses the admin
    connection. The secure path uses the least-privilege application role that
    the Azure seed step creates.
    """
    settings = get_settings()
    conninfo = (
        settings.pg_app_connection
        if settings.enable_tool_least_priv
        else settings.pg_admin_connection
    )
    if not conninfo:
        which = "PG_APP_CONNECTION" if settings.enable_tool_least_priv else "PG_ADMIN_CONNECTION"
        raise ToolError(f"{which} is required when OFFLINE_MODE=false.")
    try:
        import psycopg  # noqa: PLC0415
        from psycopg.rows import dict_row  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - dependency is optional in offline tests
        raise ToolError("Install psycopg[binary] to use Azure PostgreSQL.") from exc
    return psycopg.connect(conninfo, row_factory=dict_row)


def reset_offline_db() -> None:
    """Drop and reseed the local SQLite DB (used by tests/scripts)."""
    with _lock:
        if _OFFLINE_DB.exists():
            _OFFLINE_DB.unlink()
    _offline_conn().close()


def _conn():
    settings = get_settings()
    return _offline_conn() if settings.offline_mode else _postgres_conn()


def _set_security_context(conn: Any, *, caller_id: str | None, customer_id: str | None = None) -> None:
    settings = get_settings()
    if settings.offline_mode or not settings.enable_tool_least_priv:
        return
    owner_user_id = settings.default_owner_user_id
    conn.execute("SELECT set_config('app.owner_user_id', %s, true)", (owner_user_id,))
    if customer_id or caller_id:
        conn.execute("SELECT set_config('app.customer_id', %s, true)", (customer_id or caller_id,))


# ---------------------------------------------------------------------------
# Internal query helpers
# ---------------------------------------------------------------------------
def _rows_to_dicts(rows: Iterable[Any]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def _ph() -> str:
    """Parameter placeholder for the active database driver."""
    return "?" if get_settings().offline_mode else "%s"


def _authorize(caller_id: str | None, customer_id: str) -> None:
    """Secure mode: a caller may only access their own customer record.

    LAB-VULN(V4): in the vulnerable baseline this check is skipped entirely,
    so any customer_id can be read by anyone (IDOR / broken object-level authZ).
    """
    settings = get_settings()
    if not settings.enable_tool_least_priv:
        return  # vulnerable: no object-level authorization
    if caller_id is None or caller_id != customer_id:
        raise ToolError(
            f"Access denied: principal '{caller_id}' may not access customer "
            f"'{customer_id}'."
        )


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------
def get_accounts(customer_id: str, caller_id: str | None = None) -> list[dict[str, Any]]:
    """Return accounts + balances for a customer."""
    _authorize(caller_id, customer_id)
    conn = _conn()
    settings = get_settings()
    ph = _ph()
    try:
        _set_security_context(conn, caller_id=caller_id, customer_id=customer_id)
        if settings.enable_tool_least_priv:
            cur = conn.execute(
                "SELECT account_id, account_type, balance, currency "
                f"FROM accounts WHERE customer_id = {ph}",
                (customer_id,),
            )
        else:
            # LAB-VULN(V4): string-interpolated SQL -> injection.
            # e.g. customer_id = "x' OR '1'='1" dumps every customer's accounts.
            query = (
                "SELECT account_id, account_type, balance, currency "
                f"FROM accounts WHERE customer_id = '{customer_id}'"
            )
            cur = conn.execute(query)
        return _rows_to_dicts(cur.fetchall())
    finally:
        conn.close()


def get_transactions(
    account_id: str, limit: int = 20, caller_id: str | None = None
) -> list[dict[str, Any]]:
    """Return recent transactions for an account."""
    conn = _conn()
    settings = get_settings()
    ph = _ph()
    try:
        _set_security_context(conn, caller_id=caller_id)
        if settings.enable_tool_least_priv:
            # Verify ownership before returning rows.
            owner = conn.execute(
                f"SELECT customer_id FROM accounts WHERE account_id = {ph}",
                (account_id,),
            ).fetchone()
            if owner is None:
                return []
            _authorize(caller_id, owner["customer_id"])
            cur = conn.execute(
                "SELECT txn_id, account_id, amount, description, posted_at "
                f"FROM transactions WHERE account_id = {ph} "
                f"ORDER BY posted_at DESC LIMIT {ph}",
                (account_id, limit),
            )
        else:
            # LAB-VULN(V4): injection + no ownership check.
            query = (
                "SELECT txn_id, account_id, amount, description, posted_at "
                f"FROM transactions WHERE account_id = '{account_id}' "
                f"ORDER BY posted_at DESC LIMIT {limit}"
            )
            cur = conn.execute(query)
        return _rows_to_dicts(cur.fetchall())
    finally:
        conn.close()


def get_customer_profile(customer_id: str, caller_id: str | None = None) -> dict[str, Any]:
    """Return a customer's profile, including **PII** (SSN, email, address).

    This is the tool the V3 demo leans on: in the vulnerable baseline the SSN
    and contact details flow straight back to the caller (and into the logs)
    with no redaction. Module 3 redacts them on the way out.
    """
    _authorize(caller_id, customer_id)
    conn = _conn()
    settings = get_settings()
    ph = _ph()
    try:
        _set_security_context(conn, caller_id=caller_id, customer_id=customer_id)
        if settings.enable_tool_least_priv:
            row = conn.execute(
                "SELECT customer_id, full_name, email, ssn, address "
                f"FROM customers WHERE customer_id = {ph}",
                (customer_id,),
            ).fetchone()
        else:
            # LAB-VULN(V4): string-interpolated SQL -> injection.
            row = conn.execute(
                "SELECT customer_id, full_name, email, ssn, address "
                f"FROM customers WHERE customer_id = '{customer_id}'"
            ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def get_credit_score(customer_id: str, caller_id: str | None = None) -> dict[str, Any]:
    """Return a customer's (sensitive) credit score."""
    _authorize(caller_id, customer_id)
    conn = _conn()
    ph = _ph()
    try:
        _set_security_context(conn, caller_id=caller_id, customer_id=customer_id)
        row = conn.execute(
            "SELECT customer_id, score, bureau, updated_at "
            f"FROM credit_scores WHERE customer_id = {ph}",
            (customer_id,),
        ).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def transfer_funds(
    from_account: str,
    to_account: str,
    amount: float,
    caller_id: str | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    """High-risk, state-changing tool: move money between accounts.

    LAB-VULN(V4): in the vulnerable baseline this executes immediately with no
    human confirmation and on a read/write admin connection. In secure mode the
    Transactions agent must obtain explicit human approval (HITL) first; an
    unapproved call is refused here as defense in depth.
    """
    settings = get_settings()
    if settings.enable_hitl and not approved:
        raise ToolError(
            "transfer_funds requires human approval (HITL) before execution."
        )
    conn = _conn()
    ph = _ph()
    try:
        _set_security_context(conn, caller_id=caller_id)
        if settings.enable_tool_least_priv:
            src = conn.execute(
                f"SELECT customer_id, balance FROM accounts WHERE account_id = {ph}",
                (from_account,),
            ).fetchone()
            if src is None:
                raise ToolError("Source account not found.")
            _authorize(caller_id, src["customer_id"])
            if src["balance"] < amount:
                raise ToolError("Insufficient funds.")
            conn.execute(
                f"UPDATE accounts SET balance = balance - {ph} WHERE account_id = {ph}",
                (amount, from_account),
            )
            conn.execute(
                f"UPDATE accounts SET balance = balance + {ph} WHERE account_id = {ph}",
                (amount, to_account),
            )
        else:
            # LAB-VULN(V4): no authZ, no balance check, immediate execution.
            conn.execute(
                f"UPDATE accounts SET balance = balance - {amount} "
                f"WHERE account_id = '{from_account}'"
            )
            conn.execute(
                f"UPDATE accounts SET balance = balance + {amount} "
                f"WHERE account_id = '{to_account}'"
            )
        conn.commit()
        return {
            "status": "completed",
            "from": from_account,
            "to": to_account,
            "amount": amount,
        }
    finally:
        conn.close()
