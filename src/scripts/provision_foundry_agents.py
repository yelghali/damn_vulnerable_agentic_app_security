"""Provision **persistent Microsoft Foundry agents** for the Zava Wealth Advisor.

Why this exists
---------------
The running app (``src/agents/model.py``) only calls *chat completions*, so the
Foundry portal's **Agents** tab stays empty — there are no first-class agent
resources to show. This script creates real, versioned agents with the Microsoft
**Azure AI Foundry project SDK** (``azure-ai-projects`` >= 2.x) so they appear in
the portal and can be invoked by name.

What it creates
---------------
1. An **Azure AI Search** index (``SEARCH_INDEX_NAME``) and uploads the markdown
   docs in ``src/data/docs`` (the Knowledge agent's RAG corpus). Uses the SIMPLE
   query type so no embedding model is required (only gpt-4.1-mini is deployed).
2. Five persistent agents via ``project.agents.create_version(...)`` +
   ``PromptAgentDefinition``:
     * ``zava-orchestrator``  — router (no tools)
     * ``zava-knowledge``     — ``AzureAISearchTool`` over the index
     * ``zava-accounts``      — ``MCPTool`` (Microsoft Azure MCP Server, postgres
                                 namespace), read-only tool allow-list
     * ``zava-transactions``  — ``MCPTool`` incl. write, ``require_approval``
                                 driven by the HITL toggle
     * ``zava-reporting``     — summary writer (no tools)

The database tool is the **Microsoft Azure MCP Server** hosted on Azure
Container Apps (see ``src/infra/containerapp.tf``); the agent reaches it at
``PG_MCP_SERVER_URL`` — no Google / third-party SDK involved.

Security toggles honoured (from ``src/config.py``)
--------------------------------------------------
* ``enable_mcp_tool_security`` (V9) -> MCP ``allowed_tools`` allow-list (secure)
  vs. no allow-list (vulnerable baseline).
* ``enable_hitl`` (V4)            -> MCP ``require_approval`` = "always"/"never".
* ``secure_mode``                 -> picks the hardened system prompt.

Run
---
    python -m src.scripts.provision_foundry_agents            # create / update
    python -m src.scripts.provision_foundry_agents --delete   # remove agents

Requires ``OFFLINE_MODE=false`` plus ``FOUNDRY_PROJECT_ENDPOINT``,
``SEARCH_ENDPOINT`` and ``PG_MCP_SERVER_URL`` (Terraform outputs). Auth uses
``DefaultAzureCredential`` (``az login``); keyless RBAC must include
*Azure AI User* on the project and *Search Index Data Contributor* /
*Search Service Contributor* on the Search service.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any

from src.cohort_seed import cohort_knowledge_documents
from src.config import get_settings

logger = logging.getLogger("zava.provision")

# Agent names shown in the Foundry portal Agents tab.
AGENT_ORCHESTRATOR = "zava-orchestrator"
AGENT_KNOWLEDGE = "zava-knowledge"
AGENT_ACCOUNTS = "zava-accounts"
AGENT_TRANSACTIONS = "zava-transactions"
AGENT_REPORTING = "zava-reporting"
ALL_AGENTS = [
    AGENT_ORCHESTRATOR,
    AGENT_KNOWLEDGE,
    AGENT_ACCOUNTS,
    AGENT_TRANSACTIONS,
    AGENT_REPORTING,
]

# Microsoft Azure MCP Server — postgres namespace tool names.
# Read-only surface vs. the query tool that can also mutate data.
MCP_POSTGRES_READ_TOOLS = [
    "postgres_list",
    "postgres_table_schema_get",
    "postgres_server_config_get",
    "postgres_server_param_get",
]
MCP_POSTGRES_QUERY_TOOL = "postgres_database_query"

_DOCS_DIR = Path(__file__).resolve().parents[1] / "data" / "docs"
_FRONT_MATTER = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)


# ---------------------------------------------------------------------------
# Document parsing (mirrors src/agents/tools/search.py front-matter handling).
# ---------------------------------------------------------------------------
def _load_docs() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    if not _DOCS_DIR.exists():
        return docs
    for path in sorted(_DOCS_DIR.glob("*.md")):
        raw = path.read_text(encoding="utf-8")
        meta: dict[str, Any] = {"group_ids": []}
        body = raw
        m = _FRONT_MATTER.match(raw)
        if m:
            for line in m.group(1).splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    k, v = k.strip(), v.strip()
                    if k == "group_ids":
                        meta[k] = [g.strip() for g in v.strip("[]").split(",") if g.strip()]
                    else:
                        meta[k] = v
            body = m.group(2)
        docs.append(
            {
                "id": path.stem,
                "title": meta.get("title", path.stem),
                "url": meta.get("url", ""),
                "group_ids": meta.get("group_ids", []),
                "content": body.strip(),
            }
        )
    return docs


# ---------------------------------------------------------------------------
# Azure AI Search index + upload.
# ---------------------------------------------------------------------------
def _search_credential(settings: Any):
    from azure.core.credentials import AzureKeyCredential  # noqa: PLC0415
    from azure.identity import DefaultAzureCredential  # noqa: PLC0415

    if settings.search_key:
        return AzureKeyCredential(settings.search_key)
    return DefaultAzureCredential()


def ensure_search_index(settings: Any) -> None:
    """Create the index (if missing) and (re)upload the local docs."""
    from azure.search.documents import SearchClient  # noqa: PLC0415
    from azure.search.documents.indexes import SearchIndexClient  # noqa: PLC0415
    from azure.search.documents.indexes.models import (  # noqa: PLC0415
        SearchableField,
        SearchField,
        SearchFieldDataType,
        SearchIndex,
        SimpleField,
    )

    if not settings.search_endpoint:
        raise SystemExit("SEARCH_ENDPOINT is not set — cannot create the AI Search index.")

    cred = _search_credential(settings)
    index_name = settings.search_index_name

    index_client = SearchIndexClient(endpoint=settings.search_endpoint, credential=cred)
    fields = [
        SimpleField(name="id", type=SearchFieldDataType.String, key=True),
        SearchableField(name="title", type=SearchFieldDataType.String),
        SearchableField(name="content", type=SearchFieldDataType.String),
        SimpleField(name="url", type=SearchFieldDataType.String),
        # Document-level security (V5): filter with group_ids/any(...).
        SearchField(
            name="group_ids",
            type=SearchFieldDataType.Collection(SearchFieldDataType.String),
            filterable=True,
            facetable=True,
        ),
    ]
    index_client.create_or_update_index(SearchIndex(name=index_name, fields=fields))
    logger.info("AI Search: index '%s' ready", index_name)

    docs = _load_docs()
    docs.extend(cohort_knowledge_documents(settings.cohort_user_count, settings.cohort_user_prefix))
    if not docs:
        logger.warning("AI Search: no documents found in %s", _DOCS_DIR)
        return
    search_client = SearchClient(
        endpoint=settings.search_endpoint, index_name=index_name, credential=cred
    )
    search_client.upload_documents(documents=docs)
    logger.info("AI Search: uploaded %d document(s)", len(docs))


# ---------------------------------------------------------------------------
# Foundry project connection resolution (for the AI Search tool).
# ---------------------------------------------------------------------------
def _resolve_search_connection_id(project: Any, settings: Any) -> str:
    """Return the project-connection id for the AI Search service.

    The connection must be created beforehand (portal one-click, or
    `az cognitiveservices account project connection create`). We resolve it by
    the configured name; falling back to the name itself if the SDK accepts it.
    """
    name = settings.search_connection_name
    try:
        conn = project.connections.get(name=name)
        conn_id = getattr(conn, "id", None) or getattr(conn, "name", name)
        logger.info("Foundry: resolved AI Search connection '%s'", name)
        return conn_id
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Foundry: could not resolve AI Search connection '%s' (%s). "
            "Create it in the portal (Connected resources -> Azure AI Search) "
            "or with `az cognitiveservices account project connection create`, "
            "then set SEARCH_CONNECTION_NAME. Falling back to the raw name.",
            name,
            exc,
        )
        return name


# ---------------------------------------------------------------------------
# Tool builders.
# ---------------------------------------------------------------------------
def _search_tool(connection_id: str, settings: Any):
    from azure.ai.projects.models import (  # noqa: PLC0415
        AISearchIndexResource,
        AzureAISearchQueryType,
        AzureAISearchTool,
        AzureAISearchToolResource,
    )

    return AzureAISearchTool(
        azure_ai_search=AzureAISearchToolResource(
            indexes=[
                AISearchIndexResource(
                    project_connection_id=connection_id,
                    index_name=settings.search_index_name,
                    # SIMPLE keyword search — no embedding deployment needed.
                    query_type=AzureAISearchQueryType.SIMPLE,
                    top_k=5,
                )
            ]
        )
    )


def _postgres_mcp_tool(settings: Any, *, allow_write: bool):
    """Microsoft Azure MCP Server (postgres namespace) as a Foundry MCP tool."""
    from azure.ai.projects.models import MCPTool  # noqa: PLC0415

    if not settings.pg_mcp_server_url:
        raise SystemExit("PG_MCP_SERVER_URL is not set — deploy the Azure MCP Server (containerapp.tf).")

    # V9: secure mode pins an allow-list; vulnerable baseline exposes all tools.
    allowed: list[str] | None = None
    if settings.enable_mcp_tool_security:
        allowed = list(MCP_POSTGRES_READ_TOOLS)
        if allow_write:
            allowed.append(MCP_POSTGRES_QUERY_TOOL)

    # V4 (HITL): write-capable tools require human approval in secure mode.
    require_approval = "always" if (allow_write and settings.enable_hitl) else "never"

    return MCPTool(
        server_label="zava_postgres",
        server_url=settings.pg_mcp_server_url,
        allowed_tools=allowed,
        require_approval=require_approval,
    )


# ---------------------------------------------------------------------------
# Agent instructions.
# ---------------------------------------------------------------------------
def _load_system_prompt() -> str:
    from src.agents.prompts import load_system_prompt  # noqa: PLC0415

    return load_system_prompt("orchestrator")


def _build_definitions(project: Any, settings: Any) -> dict[str, Any]:
    from azure.ai.projects.models import PromptAgentDefinition  # noqa: PLC0415

    model = settings.foundry_model_deployment
    base_prompt = _load_system_prompt()

    search_conn = _resolve_search_connection_id(project, settings)

    knowledge_instructions = (
        f"{base_prompt}\n\n"
        "You are the Knowledge specialist. Answer questions about Zava policies, "
        "fees, disclosures and terms using ONLY the Azure AI Search tool results. "
        "Cite the document titles you used and never invent figures."
    )
    accounts_instructions = (
        f"{base_prompt}\n\n"
        "You are the Accounts specialist. Use the PostgreSQL tool to read the "
        "authenticated customer's accounts, balances, transactions and credit "
        "score. Read only — never modify data."
    )
    transactions_instructions = (
        f"{base_prompt}\n\n"
        "You are the Transactions specialist. You may move funds or email "
        "statements via the PostgreSQL tool. State-changing actions require "
        "explicit human confirmation before you proceed."
    )
    reporting_instructions = (
        f"{base_prompt}\n\n"
        "You are the Reporting specialist. Summarise the customer's finances "
        "into a concise report from the data you are given; do not fabricate "
        "numbers."
    )
    orchestrator_instructions = (
        f"{base_prompt}\n\n"
        "You are the Orchestrator. Route each request to the right specialist: "
        f"'{AGENT_KNOWLEDGE}' for documents/policies/fees, "
        f"'{AGENT_ACCOUNTS}' for balances/transactions/credit, "
        f"'{AGENT_TRANSACTIONS}' for transfers/statements, "
        f"'{AGENT_REPORTING}' for summaries/reports."
    )

    return {
        AGENT_ORCHESTRATOR: PromptAgentDefinition(
            model=model, instructions=orchestrator_instructions
        ),
        AGENT_KNOWLEDGE: PromptAgentDefinition(
            model=model,
            instructions=knowledge_instructions,
            tools=[_search_tool(search_conn, settings)],
        ),
        AGENT_ACCOUNTS: PromptAgentDefinition(
            model=model,
            instructions=accounts_instructions,
            tools=[_postgres_mcp_tool(settings, allow_write=False)],
        ),
        AGENT_TRANSACTIONS: PromptAgentDefinition(
            model=model,
            instructions=transactions_instructions,
            tools=[_postgres_mcp_tool(settings, allow_write=True)],
        ),
        AGENT_REPORTING: PromptAgentDefinition(
            model=model, instructions=reporting_instructions
        ),
    }


# ---------------------------------------------------------------------------
# Orchestration.
# ---------------------------------------------------------------------------
def _project_client(settings: Any):
    from azure.ai.projects import AIProjectClient  # noqa: PLC0415
    from azure.identity import DefaultAzureCredential  # noqa: PLC0415

    if not settings.foundry_project_endpoint:
        raise SystemExit("FOUNDRY_PROJECT_ENDPOINT is not set — point it at your Foundry project.")
    return AIProjectClient(
        endpoint=settings.foundry_project_endpoint,
        credential=DefaultAzureCredential(),
    )


def provision() -> None:
    settings = get_settings()
    if settings.offline_mode:
        raise SystemExit("OFFLINE_MODE is true — set OFFLINE_MODE=false to provision Foundry agents.")

    ensure_search_index(settings)

    project = _project_client(settings)
    definitions = _build_definitions(project, settings)

    for name, definition in definitions.items():
        version = project.agents.create_version(agent_name=name, definition=definition)
        ver = getattr(version, "version", getattr(version, "id", "?"))
        logger.info("Foundry agent '%s' provisioned (version %s)", name, ver)

    posture = "SECURE" if settings.secure_mode else "VULNERABLE baseline"
    logger.info(
        "Done. %d agents are now visible in the Foundry portal Agents tab (%s).",
        len(definitions),
        posture,
    )


def delete_agents() -> None:
    settings = get_settings()
    if settings.offline_mode:
        raise SystemExit("OFFLINE_MODE is true — nothing to delete.")
    project = _project_client(settings)
    for name in ALL_AGENTS:
        try:
            project.agents.delete(agent_name=name)
            logger.info("Deleted Foundry agent '%s'", name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not delete '%s' (%s)", name, exc)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Provision persistent Foundry agents for the Zava lab.")
    parser.add_argument("--delete", action="store_true", help="Delete the provisioned agents instead of creating them.")
    args = parser.parse_args(argv)

    if args.delete:
        delete_agents()
    else:
        provision()
    return 0


if __name__ == "__main__":
    sys.exit(main())
