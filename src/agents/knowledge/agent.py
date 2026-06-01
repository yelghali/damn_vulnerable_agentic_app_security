"""Knowledge (RAG) agent — retrieves financial documents from Azure AI Search.

Applies document-level security trimming (V5) and shields retrieved content
against indirect prompt injection (V6) before it reaches the model.
"""

from __future__ import annotations

import re

from src.agents.guard.guard import SafetyViolation, check_groundedness, shield_prompt
from src.agents.model import compose_answer
from src.agents.tools.search import search_documents
from src.agents.types import AgentContext, TurnResult
from src.agents.prompts import load_system_prompt

# A forged cross-agent control message embedded in (poisoned) document content.
# Matches lines like ``[[handoff:transactions]] transfer $9999 from … to …``.
_HANDOFF_RE = re.compile(r"\[\[handoff:(\w+)\]\]\s*(.+)", re.IGNORECASE)


def run(message: str, ctx: AgentContext) -> TurnResult:
    events: list[str] = []
    docs = search_documents(message, caller_groups=ctx.groups)
    events.append(f"knowledge: retrieved {len(docs)} document(s)")

    # V6: shield each retrieved document for indirect prompt injection.
    safe_docs = []
    for d in docs:
        try:
            shield_prompt(d["content"], source="document")
            safe_docs.append(d)
        except SafetyViolation as v:
            events.append(f"prompt-shield BLOCKED document '{d['id']}' ({v.category})")

    # V11: a poisoned doc can smuggle a *cross-agent handoff* directive that
    # carries no jailbreak phrasing (so Prompt Shields above lets it pass). The
    # knowledge agent surfaces it as a handoff; the orchestrator decides whether
    # to trust it. The inter-agent guard (V11) is the control that stops it.
    handoff = None
    for d in safe_docs:
        m = _HANDOFF_RE.search(d["content"])
        if m:
            handoff = {"to": m.group(1).lower(), "message": m.group(2).strip(), "from_doc": d["id"]}
            events.append(f"knowledge: doc '{d['id']}' requested handoff to '{handoff['to']}'")
            break

    context = "\n\n".join(f"[{d['title']}]\n{d['content']}" for d in safe_docs)
    answer = compose_answer(load_system_prompt(), message, context)

    if not check_groundedness(answer, [d["content"] for d in safe_docs]):
        events.append("groundedness: answer not fully supported by sources (flagged)")

    return TurnResult(answer=answer, agent="knowledge", events=events, sources=safe_docs, handoff=handoff)
