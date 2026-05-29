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

Offline mode reads markdown files from ``data/docs`` (front-matter ``group_ids``)
so retrieval + trimming are testable without Azure.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from src.config import get_settings

_DOCS_DIR = Path(__file__).resolve().parents[2] / "data" / "docs"
_FRONT_MATTER = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)


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
    """
    settings = get_settings()
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

    if settings.enable_doc_security:
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
