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

from src.agents.tools import db
from src.config import get_settings


def seed_offline() -> None:
    """Drop and reseed the local SQLite store, then report row counts."""
    db.reset_offline_db()
    conn = db._offline_conn()  # noqa: SLF001 - internal helper reuse for the script
    try:
        tables = ("accounts", "transactions", "credit_scores")
        for table in tables:
            count = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
            print(f"  seeded {table:<14} {count} row(s)")
    finally:
        conn.close()
    print("Offline SQLite store reseeded.")


def seed_azure() -> None:
    """Seed PostgreSQL + upload/index sample docs (Azure mode).

    Implemented as a guided placeholder: wire to your Foundry/AI Search/Postgres
    deployment outputs. Kept out of the offline path on purpose.
    """
    raise SystemExit(
        "Azure seeding requires OFFLINE_MODE=false and configured "
        "PG_ADMIN_CONNECTION / SEARCH_ENDPOINT / Blob settings. "
        "See docs/workshop.md, Module 0."
    )


def main() -> None:
    settings = get_settings()
    if settings.offline_mode:
        print("Seeding in OFFLINE mode (local SQLite)...")
        seed_offline()
    else:
        print("Seeding in AZURE mode (PostgreSQL + AI Search)...")
        seed_azure()


if __name__ == "__main__":
    main()
