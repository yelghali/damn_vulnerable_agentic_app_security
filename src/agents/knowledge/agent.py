"""Knowledge (RAG) agent — retrieves financial documents from Azure AI Search.

Applies document-level security trimming (V5) and shields retrieved content
against indirect prompt injection (V6) before it reaches the model.
"""

from __future__ import annotations

from src.agents.guard.guard import SafetyViolation, check_groundedness, shield_prompt
from src.agents.model import compose_answer
from src.agents.tools.search import search_documents
from src.agents.types import AgentContext, TurnResult
from src.agents.prompts import load_system_prompt


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

    context = "\n\n".join(f"[{d['title']}]\n{d['content']}" for d in safe_docs)
    answer = compose_answer(load_system_prompt(), message, context)

    if not check_groundedness(answer, [d["content"] for d in safe_docs]):
        events.append("groundedness: answer not fully supported by sources (flagged)")

    return TurnResult(answer=answer, agent="knowledge", events=events, sources=safe_docs)
