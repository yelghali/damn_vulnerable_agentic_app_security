"""Synthetic cohort seed helpers shared by SQLite, PostgreSQL, and AI Search.

The base lab seed keeps two named personas for predictable walkthroughs. These
helpers extend that seed for classroom cohorts so generated users such as
``user_27`` also have matching ``CUST-1027`` financial rows and group-scoped
knowledge documents.
"""

from __future__ import annotations

from typing import Any

from src.scripts.setup_lab_users import LabUser, build_users

BASE_PERSONA_COUNT = 2


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def cohort_users(count: int, prefix: str = "user") -> list[LabUser]:
    """Return generated cohort users using the same mapping as setup scripts."""
    normalized = max(BASE_PERSONA_COUNT, min(count, 100))
    return build_users(
        normalized,
        prefix,
        "example.onmicrosoft.com",
        group_assignment="round-robin",
        include_manager=False,
    )


def cohort_financial_seed_sql(count: int, prefix: str = "user") -> str:
    """Generate SQL rows for users beyond the two hand-authored personas."""
    customer_rows: list[str] = []
    account_rows: list[str] = []
    transaction_rows: list[str] = []
    credit_score_rows: list[str] = []

    for user in cohort_users(count, prefix)[BASE_PERSONA_COUNT:]:
        index = int(user.user_id.rsplit("_", 1)[1])
        customer_id = user.customer_id
        owner_user_id = user.owner_user_id
        full_name = f"Zava Learner {index:02d}"
        email = f"{owner_user_id}@example.com"
        ssn = f"{900 + (index % 100):03d}-{index % 100:02d}-{index:04d}"
        address = f"{100 + index} Cohort Ave, Redmond WA"
        checking_account = f"ACC-{index}00001"
        savings_account = f"ACC-{index}00002"
        checking_balance = 1800 + (index * 137.25)
        savings_balance = 8000 + (index * 913.50)
        score = 650 + ((index * 17) % 120)

        customer_rows.append(
            "(" + ", ".join(
                _quote(value)
                for value in (customer_id, owner_user_id, full_name, email, ssn, address)
            ) + ")"
        )
        account_rows.extend(
            [
                f"({_quote(checking_account)}, {_quote(customer_id)}, {_quote(owner_user_id)}, 'checking', {checking_balance:.2f}, 'USD')",
                f"({_quote(savings_account)}, {_quote(customer_id)}, {_quote(owner_user_id)}, 'savings', {savings_balance:.2f}, 'USD')",
            ]
        )
        transaction_rows.extend(
            [
                f"('TXN-{index}-1', {_quote(checking_account)}, -42.15, 'Cohort coffee shop', '2026-05-02')",
                f"('TXN-{index}-2', {_quote(checking_account)}, 2200.00, 'Payroll', '2026-05-05')",
                f"('TXN-{index}-3', {_quote(savings_account)}, 125.00, 'Monthly savings transfer', '2026-05-06')",
            ]
        )
        credit_score_rows.append(
            f"({_quote(customer_id)}, {score}, 'Experian', '2026-04-30')"
        )

    if not customer_rows:
        return ""
    return "\n\n".join(
        [
            "INSERT INTO customers VALUES\n" + ",\n".join(customer_rows) + ";",
            "INSERT INTO accounts VALUES\n" + ",\n".join(account_rows) + ";",
            "INSERT INTO transactions VALUES\n" + ",\n".join(transaction_rows) + ";",
            "INSERT INTO credit_scores VALUES\n" + ",\n".join(credit_score_rows) + ";",
        ]
    )


def cohort_knowledge_documents(count: int, prefix: str = "user") -> list[dict[str, Any]]:
    """Generate group-scoped sample docs for larger AI Search cohorts."""
    docs: list[dict[str, Any]] = []
    for user in cohort_users(count, prefix):
        groups = list(user.assigned_groups)
        docs.append(
            {
                "id": f"cohort-{user.user_id.replace('_', '-')}-welcome",
                "title": f"Cohort note for {user.user_id}",
                "url": "",
                "group_ids": groups,
                "content": (
                    f"Synthetic classroom note for {user.user_id} / {user.customer_id}. "
                    f"This document is scoped to {', '.join(groups)} through the AI Search group_ids field. "
                    "It is safe sample data for document-level security testing."
                ),
            }
        )
    return docs
