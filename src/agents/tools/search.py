"""RAG retrieval tool backed by Azure AI Search.

Powers the Knowledge agent. Two behaviours:

* **Vulnerable baseline** (``enable_doc_security=False``)
    - returns every matching chunk regardless of who is asking  -> data
      over-sharing across customers (LAB-VULN V5)
    - ingests/returns document content verbatim, including a *poisoned* doc
      that carries an indirect prompt-injection payload (LAB-VULN V6)
* **Secure path** (``enable_doc_security=True``)
    - applies **document-level security trimming**: only chunks whose
      ``group_ids`` intersect the caller's Entra group/object IDs are returned,
      mirroring the Azure AI Search ``search.in()`` filter pattern.

Offline mode reads markdown files from ``data/docs`` for the vulnerable baseline.
When document security is enabled, Azure AI Search is required so ACL trimming
runs server-side with ``search.in()`` instead of as a local approximation.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from src.config import get_settings

_DOCS_DIR = Path(__file__).resolve().parents[2] / "data" / "docs"
_FRONT_MATTER = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)
logger = logging.getLogger("zava.search")


class SearchConfigurationError(RuntimeError):
    """Raised when a required Azure AI Search security control is unavailable."""


def _is_admin(caller_groups: list[str] | None = None) -> bool:
    configured = {g.strip() for g in get_settings().admin_groups.split(",") if g.strip()}
    return bool(configured.intersection(caller_groups or []))


def _load_offline_docs() -> list[dict[str, Any]]:
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
                "group_ids": meta.get("group_ids", []),
                "content": body.strip(),
            }
        )
    return docs


def search_documents(
    query: str, caller_groups: list[str] | None = None, top: int = 3
) -> list[dict[str, Any]]:
    """Retrieve document chunks relevant to ``query``.

    ``caller_groups`` are the authenticated principal's Entra group/object IDs.
    Uses Azure AI Search when ``SEARCH_ENDPOINT`` is configured. If document-level
    security is enabled, Azure Search is required so trimming runs server-side.
    The offline markdown corpus remains only for the intentionally vulnerable
    local baseline.
    """
    settings = get_settings()
    if settings.search_endpoint:
        try:
            return _azure_search(query, caller_groups, top, settings)
        except Exception as exc:  # noqa: BLE001 - Azure failure must not leak untrimmed docs
            raise SearchConfigurationError(f"Azure AI Search failed closed: {exc}") from exc

    if settings.enable_doc_security:
        raise SearchConfigurationError(
            "Document security is enabled but SEARCH_ENDPOINT is not configured."
        )

    docs = _load_offline_docs()

    # naive keyword relevance (offline). Azure AI Search does vector + semantic.
    terms = [t for t in re.split(r"\W+", query.lower()) if t]
    scored = []
    for d in docs:
        hay = (d["title"] + " " + d["content"]).lower()
        score = sum(hay.count(t) for t in terms)
        if score:
            scored.append((score, d))
    scored.sort(key=lambda x: x[0], reverse=True)
    results = [d for _, d in scored[:top]] or docs[:top]

    if settings.enable_doc_security and not _is_admin(caller_groups):
        # SECURE: document-level security trimming.
        # Mirrors AI Search:  group_ids/any(g:search.in(g, '<caller groups>'))
        groups = set(caller_groups or [])
        results = [
            d for d in results
            if not d["group_ids"] or groups.intersection(d["group_ids"])
        ]
    # LAB-VULN(V5): otherwise every chunk is returned to every caller.
    return [
        {"id": d["id"], "title": d["title"], "content": d["content"]}
        for d in results
    ]


def _azure_search(
    query: str, caller_groups: list[str] | None, top: int, settings: Any
) -> list[dict[str, Any]]:
    """Genuine Azure AI Search query with optional document-level security trimming.

    When ``enable_doc_security`` is on, the trimming runs **server-side** via an
    OData ``search.in()`` filter on the ``group_ids`` field, so untrimmed chunks
    never leave the index. When off, no filter is applied -> every chunk is
    returned to every caller (LAB-VULN V5).
    """
    from azure.core.credentials import AzureKeyCredential
    from azure.identity import DefaultAzureCredential
    from azure.search.documents import SearchClient

    credential = AzureKeyCredential(settings.search_key) if settings.search_key else DefaultAzureCredential()

    client = SearchClient(
        endpoint=settings.search_endpoint,
        index_name=settings.search_index_name,
        credential=credential,
    )
    search_filter: str | None = None
    if settings.enable_doc_security and not _is_admin(caller_groups):
        groups = ",".join(g.replace("'", "").replace(",", "") for g in (caller_groups or []))
        # Only return docs with no ACL or whose group_ids intersect the caller's.
        search_filter = f"not group_ids/any() or group_ids/any(g: search.in(g, '{groups}', ','))"
    results = client.search(
        search_text=query,
        filter=search_filter,
        top=top,
        select=["id", "title", "content"],
    )
    return [
        {"id": r.get("id"), "title": r.get("title"), "content": r.get("content")}
        for r in results
    ]
