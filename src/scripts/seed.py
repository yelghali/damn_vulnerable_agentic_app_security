"""Seed the Zava data layer (Module 0).

* **Offline** (``OFFLINE_MODE=true``, default): drop + reseed the local SQLite
  database from ``src/data/seed_offline.sql`` so the app + tests run with no
  Azure. This is what the workshop's *Verify* steps rely on.
* **Azure** (``OFFLINE_MODE=false``): seed Azure Database for PostgreSQL from
  the same logical schema and upload the sample documents (including the one
  *poisoned* doc used in Modules 2 & 8) to Blob, then index them in Azure AI
  Search. The Azure path is constructed lazily so offline runs need no Azure
  SDKs or credentials.

Run with: ``python -m src.scripts.seed``
"""

from __future__ import annotations

import argparse
from pathlib import Path
from urllib.parse import unquote, urlparse

from src.agents.tools import db
from src.cohort_seed import cohort_financial_seed_sql
from src.config import get_settings

_ROOT = Path(__file__).resolve().parents[1]
_OFFLINE_SEED = _ROOT / "data" / "seed_offline.sql"


def _postgres_seed_sql(cohort_count: int, cohort_prefix: str) -> str:
    sql = _OFFLINE_SEED.read_text(encoding="utf-8")
    sql = sql.replace(
        "CREATE TABLE customers",
        "DROP TABLE IF EXISTS credit_scores;\n"
        "DROP TABLE IF EXISTS transactions;\n"
        "DROP TABLE IF EXISTS accounts;\n"
        "DROP TABLE IF EXISTS customers;\n\n"
        "CREATE TABLE customers",
    )
    sql = sql.replace("REAL NOT NULL", "NUMERIC(12,2) NOT NULL")
    extra_seed = cohort_financial_seed_sql(cohort_count, cohort_prefix)
    if extra_seed:
        sql = sql.rstrip() + "\n\n" + extra_seed + "\n"
    return sql


def _app_role_from_conninfo(conninfo: str) -> tuple[str, str | None]:
    parsed = urlparse(conninfo)
    user = unquote(parsed.username or "zava_app_ro")
    password = unquote(parsed.password) if parsed.password else None
    if not user.replace("_", "").isalnum():
        raise SystemExit("PG_APP_CONNECTION username must be alphanumeric/underscore for lab seeding.")
    return user, password


def seed_offline(cohort_count: int | None = None, cohort_prefix: str | None = None) -> None:
    """Drop and reseed the local SQLite store, then report row counts."""
    settings = get_settings()
    cohort_count = cohort_count if cohort_count is not None else settings.cohort_user_count
    cohort_prefix = cohort_prefix if cohort_prefix is not None else settings.cohort_user_prefix
    db.reset_offline_db(cohort_count=cohort_count, cohort_prefix=cohort_prefix)
    conn = db._offline_conn()  # noqa: SLF001 - internal helper reuse for the script
    try:
        tables = ("accounts", "transactions", "credit_scores")
        for table in tables:
            count = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            print(f"  seeded {table:<14} {count} row(s)")
    finally:
        conn.close()
    print(f"Offline SQLite store reseeded for {cohort_count} cohort user(s).")


def seed_azure(cohort_count: int | None = None, cohort_prefix: str | None = None) -> None:
    """Seed PostgreSQL + upload/index sample docs (Azure mode).

    Uses ``PG_ADMIN_CONNECTION`` for schema/data creation. If AI Search is
    configured, it also creates the workshop RAG index and uploads the sample
    documents used by the Knowledge agent.
    """
    settings = get_settings()
    cohort_count = cohort_count if cohort_count is not None else settings.cohort_user_count
    cohort_prefix = cohort_prefix if cohort_prefix is not None else settings.cohort_user_prefix
    if not settings.pg_admin_connection:
        raise SystemExit("PG_ADMIN_CONNECTION is required when OFFLINE_MODE=false.")
    try:
        import psycopg  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - offline tests do not import psycopg
        raise SystemExit("Install psycopg[binary] to seed Azure PostgreSQL.") from exc

    from psycopg import sql  # noqa: PLC0415

    app_role, app_password = _app_role_from_conninfo(settings.pg_app_connection)
    with psycopg.connect(settings.pg_admin_connection) as conn:
        conn.execute(_postgres_seed_sql(cohort_count, cohort_prefix))
        role_ident = sql.Identifier(app_role)
        if app_password:
            conn.execute(
                sql.SQL(
                    "DO $$ BEGIN "
                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role}) THEN "
                    "CREATE ROLE {ident} LOGIN PASSWORD {password}; "
                    "ELSE ALTER ROLE {ident} WITH LOGIN PASSWORD {password}; "
                    "END IF; END $$;"
                ).format(
                    role=sql.Literal(app_role),
                    ident=role_ident,
                    password=sql.Literal(app_password),
                )
            )
        else:
            conn.execute(
                sql.SQL(
                    "DO $$ BEGIN "
                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {role}) THEN "
                    "CREATE ROLE {ident} LOGIN; "
                    "END IF; END $$;"
                ).format(
                    role=sql.Literal(app_role),
                    ident=role_ident,
                )
            )
        conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role_ident))
        conn.execute(
            sql.SQL("GRANT SELECT ON customers, accounts, transactions, credit_scores TO {}").format(
                role_ident
            )
        )
        for table in ("customers", "accounts", "transactions", "credit_scores"):
            conn.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(sql.Identifier(table)))
        conn.execute("DROP POLICY IF EXISTS zava_customer_owner ON customers")
        conn.execute("DROP POLICY IF EXISTS zava_account_owner ON accounts")
        conn.execute("DROP POLICY IF EXISTS zava_transaction_owner ON transactions")
        conn.execute("DROP POLICY IF EXISTS zava_credit_score_owner ON credit_scores")
        conn.execute(
            sql.SQL(
                "CREATE POLICY zava_customer_owner ON customers FOR SELECT TO {} USING ("
                "owner_user_id = current_setting('app.owner_user_id', true) "
                "OR customer_id = current_setting('app.customer_id', true))"
            ).format(role_ident)
        )
        conn.execute(
            sql.SQL(
                "CREATE POLICY zava_account_owner ON accounts FOR SELECT TO {} USING ("
                "owner_user_id = current_setting('app.owner_user_id', true) "
                "OR customer_id = current_setting('app.customer_id', true))"
            ).format(role_ident)
        )
        conn.execute(
            sql.SQL(
                "CREATE POLICY zava_transaction_owner ON transactions FOR SELECT TO {} USING ("
                "EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = transactions.account_id "
                "AND (a.owner_user_id = current_setting('app.owner_user_id', true) "
                "OR a.customer_id = current_setting('app.customer_id', true))))"
            ).format(role_ident)
        )
        conn.execute(
            sql.SQL(
                "CREATE POLICY zava_credit_score_owner ON credit_scores FOR SELECT TO {} USING ("
                "EXISTS (SELECT 1 FROM customers c WHERE c.customer_id = credit_scores.customer_id "
                "AND (c.owner_user_id = current_setting('app.owner_user_id', true) "
                "OR c.customer_id = current_setting('app.customer_id', true))))"
            ).format(role_ident)
        )
        conn.commit()
        for table in ("accounts", "transactions", "credit_scores"):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  seeded {table:<14} {count} row(s)")
    print(
        f"Azure PostgreSQL store reseeded for {cohort_count} cohort user(s); "
        f"least-privilege role '{app_role}' granted SELECT "
        "with owner_user_id row-level security policies."
    )

    if settings.search_endpoint:
        from src.scripts.provision_foundry_agents import ensure_search_index  # noqa: PLC0415

        ensure_search_index(settings)
        print(f"AI Search index '{settings.search_index_name}' created/updated.")
    else:
        print("SEARCH_ENDPOINT not set; skipped AI Search document indexing.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed Zava lab data for local or Azure mode.")
    parser.add_argument(
        "--cohort-count",
        type=int,
        default=None,
        help="Number of generated cohort users to seed. Defaults to COHORT_USER_COUNT or 2.",
    )
    parser.add_argument(
        "--cohort-prefix",
        default=None,
        help="Generated user prefix. Defaults to COHORT_USER_PREFIX or user.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = get_settings()
    cohort_count = args.cohort_count if args.cohort_count is not None else settings.cohort_user_count
    cohort_prefix = args.cohort_prefix or settings.cohort_user_prefix
    if cohort_count < 1 or cohort_count > 100:
        raise SystemExit("--cohort-count must be between 1 and 100.")
    if settings.offline_mode:
        print("Seeding in OFFLINE mode (local SQLite)...")
        seed_offline(cohort_count, cohort_prefix)
    else:
        print("Seeding in AZURE mode (PostgreSQL + AI Search)...")
        seed_azure(cohort_count, cohort_prefix)


if __name__ == "__main__":
    main()
