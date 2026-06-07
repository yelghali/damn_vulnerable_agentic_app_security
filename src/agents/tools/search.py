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
_STOP_WORDS = {
    "a", "an", "and", "are", "about", "for", "is", "me", "my", "of", "the", "to", "what", "with",
}
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


def _term_variants(term: str) -> set[str]:
    variants = {term}
    if len(term) > 3 and term.endswith("s"):
        variants.add(term[:-1])
    return variants


def search_documents(
    query: str, caller_groups: list[str] | None = None, top: int = 3
) -> list[dict[str, Any]]:
    """Retrieve document chunks relevant to ``query``.

    ``caller_groups`` are the authenticated principal's Entra group/object IDs.
    Uses Azure AI Search when ``SEARCH_ENDPOINT`` is configured for the cloud data
    plane. In ``LOCAL_DATA_MODE``, non-doc-security lab probes use the seeded
    markdown corpus so V6/V11 remain runnable without Search credentials. If
    document-level security is enabled, Azure Search is still required so trimming
    runs server-side.
    """
    settings = get_settings()
    use_local_corpus = settings.local_data_mode and not settings.enable_doc_security
    if settings.search_endpoint and not use_local_corpus:
        try:
            return _azure_search(query, caller_groups, top, settings)
        except Exception as exc:  # noqa: BLE001 - Azure failure must not leak untrimmed docs
            raise SearchConfigurationError(f"Azure AI Search failed closed: {exc}") from exc

    if settings.enable_doc_security:
        raise SearchConfigurationError(
            "Document security is enabled but SEARCH_ENDPOINT is not configured."
        )

    docs = _load_offline_docs()

    # Lightweight offline relevance. Azure AI Search does vector + semantic;
    # locally we keep only the strongest seeded-doc matches so benign prompts do
    # not pull poisoned lab documents into context unless the query is actually
    # about that attack surface.
    terms = [t for t in re.split(r"\W+", query.lower()) if t and t not in _STOP_WORDS]
    scored = []
    for d in docs:
        title = d["title"].lower()
        content = d["content"].lower()
        score = sum(
            (3 * title.count(variant)) + content.count(variant)
            for term in terms
            for variant in _term_variants(term)
        )
        if score:
            scored.append((score, d))
    scored.sort(key=lambda x: x[0], reverse=True)
    cutoff = max(1, scored[0][0] // 2) if scored else 1
    results = [d for score, d in scored[:top] if score >= cutoff]

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


def list_knowledge_documents(caller_groups: list[str] | None = None, top: int = 200) -> list[dict[str, Any]]:
    """List the knowledge corpus for the V5 document-security lab probe.

    Vulnerable mode deliberately returns every document. Secure mode requires
    Azure AI Search and applies the same server-side ``group_ids`` trimming as
    normal RAG queries.
    """
    settings = get_settings()
    use_local_corpus = settings.local_data_mode and not settings.enable_doc_security
    if settings.search_endpoint and not use_local_corpus:
        try:
            return _azure_list_documents(caller_groups, top, settings)
        except Exception as exc:  # noqa: BLE001 - Azure failure must not leak untrimmed docs
            raise SearchConfigurationError(f"Azure AI Search failed closed: {exc}") from exc

    if settings.enable_doc_security:
        raise SearchConfigurationError(
            "Document security is enabled but SEARCH_ENDPOINT is not configured."
        )

    return [
        {
            "id": doc["id"],
            "title": doc["title"],
            "content": doc["content"],
            "group_ids": doc.get("group_ids", []),
        }
        for doc in _load_offline_docs()[:top]
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


def _azure_list_documents(caller_groups: list[str] | None, top: int, settings: Any) -> list[dict[str, Any]]:
    """List docs from Azure AI Search with optional document-level security."""
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
        search_filter = f"not group_ids/any() or group_ids/any(g: search.in(g, '{groups}', ','))"
    results = client.search(
        search_text="*",
        filter=search_filter,
        top=top,
        select=["id", "title", "content", "group_ids"],
    )
    return [
        {
            "id": r.get("id"),
            "title": r.get("title"),
            "content": r.get("content"),
            "group_ids": list(r.get("group_ids") or []),
        }
        for r in results
    ]
